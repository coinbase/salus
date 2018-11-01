require 'json'
require 'salus/scanners/base'

# NPM Audit scanner integration. Flags known malicious or vulnerable
# dependencies in javascript projects.
# https://medium.com/npm-inc/npm-acquires-lift-security-258e257ef639

module Salus::Scanners
  class NPMAudit < Base
    include Salus::Formatting

    # Structure to hold the relevant information about a given adivsory
    Advisory = Struct.new(:id, :module, :title, :severity, :url, :prod?, :excepted?)

    # Some common, easily-abbreviated terms to shorten advisory titles
    TITLE_SUBSTITUTIONS = {
      'Regular Expression'    => 'Regex',
      'Denial of Service'     => 'DoS',
      'Remote Code Execution' => 'RCE',
      'Cross-Site Scripting'  => 'XSS'
    }.freeze

    # Cap title and module name length to avoid the table getting too wide
    MAX_MODULE_LENGTH = 16
    MAX_TITLE_LENGTH = 16

    # Headings for the tabulated report
    TABLE_HEADINGS = ['ID', 'Module', 'Title', 'Sev.', 'URL', 'Prod', 'Ex.'].freeze

    AUDIT_COMMAND = 'npm audit --json'.freeze
    LOCKFILE_COMMAND = 'npm install --package-lock-only'.freeze

    def run
      exception_ids = fetch_exception_ids

      Dir.chdir(@repository.path_to_repo) do
        ensure_package_lock do
          json = run_npm_audit
          report_info(:npm_audit_output, json)

          raw_advisories = json.fetch(:advisories).values

          advisories = raw_advisories.map do |advisory|
            # Each advisory corresponds to some vulnerable package, which
            # may exist as multiple versions in multiple nodes of the dependency
            # tree. advisory[:findings] is an array of objects looking roughly like
            # [
            #   { "version": "1.0.5", ..., "dev": false },
            #   { "version": "1.0.5", ..., "dev": true }
            # ]
            # where each element records an instance of the vulnerable package
            # in the dependency tree. If, for some finding, dev is false,
            # then there exists a vulnerable version of the module in the prod
            # dependency tree
            prod = advisory.fetch(:findings).any? { |finding| !finding.fetch(:dev) }

            id = advisory.fetch(:id).to_s
            excepted = exception_ids.include?(id)

            Advisory.new(
              id,
              advisory.fetch(:module_name),
              advisory.fetch(:title),
              advisory.fetch(:severity),
              advisory.fetch(:url),
              prod,
              excepted
            )
          end

          # Sort advisories with un-excepted prod vulnerabilities first,
          # and in ascending order of ID otherwise
          advisories = advisories.sort_by do |advisory|
            unexcepted_and_prod = !advisory.excepted? && advisory.prod?
            [(unexcepted_and_prod ? 0 : 1), advisory.id.to_i]
          end

          # Categorize the advisories and exceptions for informational purposes

          prod_advisories, dev_advisories = advisories.partition(&:prod?)
          unex_prod_advisories = prod_advisories.reject(&:excepted?)

          advisories_by_id = advisories.map(&:id).zip(advisories).to_h

          useful_exception_ids, useless_exception_ids = exception_ids.partition do |id|
            advisories_by_id.key?(id)
          end

          prod_exception_ids, dev_exception_ids = useful_exception_ids.partition do |id|
            advisories_by_id.fetch(id).prod?
          end

          prod_advisory_ids      = prod_advisories.map(&:id).sort_by(&:to_i)
          dev_advisory_ids       = dev_advisories.map(&:id).sort_by(&:to_i)
          unex_prod_advisory_ids = unex_prod_advisories.map(&:id).sort_by(&:to_i)
          prod_exception_ids     = prod_exception_ids.sort_by(&:to_i)
          dev_exception_ids      = dev_exception_ids.sort_by(&:to_i)
          useless_exception_ids  = useless_exception_ids.sort_by(&:to_i)

          # The _id suffix isn't super interesting information from the perspective of an
          # external consumer just drop it
          report_info(:prod_advisories,            prod_advisory_ids)
          report_info(:dev_advisories,             dev_advisory_ids)
          report_info(:unexcepted_prod_advisories, unex_prod_advisory_ids)
          report_info(:exceptions,                 useful_exception_ids)
          report_info(:prod_exceptions,            prod_exception_ids)
          report_info(:dev_exceptions,             dev_exception_ids)
          report_info(:useless_exceptions,         useless_exception_ids)

          if advisories.empty?
            log('There are no advisories against your dependencies. Hooray!')
          else
            log(tabulate_advisories(advisories) + "\n")
          end

          if unex_prod_advisory_ids.any?
            stringified_ids = unex_prod_advisory_ids.join(' ')
            log(
              "Audit failed pending the following advisory(s): #{stringified_ids}. " \
              'To fix the build, please resolve the previous advisory(s), or add exceptions.'
            )
          end

          if useless_exception_ids.any?
            stringified_ids = useless_exception_ids.join(' ')
            log(
              'The following exception(s) do not match any advisory against the directory ' \
              "and can safely be removed: #{stringified_ids}."
            )
          end

          if dev_exception_ids.any?
            stringified_ids = dev_exception_ids.join(' ')
            log(
              'The following exceptions apply only to development dependencies ' \
              "and can safely be removed: #{stringified_ids}."
            )
          end

          if unex_prod_advisories.empty?
            report_success
          else
            report_failure
          end
        end
      end
    end

    def should_run?
      @repository.package_json_present? ||
        @repository.package_lock_json_present? ||
        @repository.yarn_lock_present?
    end

    def fetch_exception_ids
      exceptions = @config.fetch('exceptions', [])

      ids = []

      exceptions.each do |exception|
        if !exception.is_a?(Hash) || exception.keys.sort != %w[advisory_id changed_by notes]
          report_error(
            'malformed exception; expected a hash with keys advisory_id, changed_by, notes',
            exception: exception
          )
          next
        end

        ids << exception.fetch('advisory_id').to_s
      end

      ids
    end

    def ensure_package_lock
      created_package_lock = false

      if !File.exist?('package-lock.json')
        shell_result = run_shell(LOCKFILE_COMMAND)

        if !shell_result.success?
          raise "`#{LOCKFILE_COMMAND}` failed with exit code #{shell_result.status}"
        end

        created_package_lock = true
      end

      yield
    ensure
      File.delete("package-lock.json") if created_package_lock
    end

    def run_npm_audit
      raw = run_shell(AUDIT_COMMAND).stdout
      json = JSON.parse(raw, symbolize_names: true)

      if json.key?(:error)
        code = json[:error][:code] || '<none>'
        summary = json[:error][:summary] || '<none>'

        message =
          "`#{AUDIT_COMMAND}` failed unexpectedly (error code #{code}):\n" \
          "```\n#{summary}\n```"

        raise message
      end

      json
    end

    def abbreviate_title(title)
      TITLE_SUBSTITUTIONS.each { |from, to| title = title.gsub(from, to) }
      title = title[0...(MAX_TITLE_LENGTH - 1)] + '~' if title.length > MAX_TITLE_LENGTH
      title
    end

    def abbreviate_module(mod)
      mod = mod[0...(MAX_MODULE_LENGTH - 1)] + '~' if mod.length > MAX_MODULE_LENGTH
      mod
    end

    def abbreviate_severity(severity)
      case severity
      when 'critical' then 'crit'
      when 'moderate' then 'mod'
      else severity
      end
    end

    def tabulate_advisories(advisories)
      table = advisories.map do |advisory|
        [
          advisory.id,
          abbreviate_module(advisory.module),
          abbreviate_title(advisory.title),
          abbreviate_severity(advisory.severity),
          advisory.url.gsub('https://', ''),
          advisory.prod? ? 'yes' : 'no',
          advisory.excepted? ? 'yes' : 'no'
        ]
      end

      tabulate(TABLE_HEADINGS, table)
    end
  end
end
