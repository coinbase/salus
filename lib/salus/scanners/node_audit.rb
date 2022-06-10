require 'json'
require 'salus/scanners/base'

# Superclass for Node package CVE scanners (Yarn and NPM).

module Salus::Scanners
  class NodeAudit < Base
    def self.scanner_type
      Salus::ScannerTypes::DEPENDENCY
    end

    include Salus::Formatting

    # Structure to hold the relevant information about a given adivsory
    Advisory = Struct.new(:id, :module, :title, :severity, :url, :prod?, :excepted?)

    # Some common, easily-abbreviated terms to shorten advisory titles
    TITLE_SUBSTITUTIONS = {
      'Regular Expression' => 'Regex',
      'Denial of Service' => 'DoS',
      'Remote Code Execution' => 'RCE',
      'Cross-Site Scripting' => 'XSS'
    }.freeze

    # Cap title and module name length to avoid the table getting too wide
    MAX_MODULE_LENGTH = 16
    MAX_TITLE_LENGTH = 16

    # Headings for the tabulated report
    TABLE_HEADINGS = ['ID', 'Module', 'Title', 'Sev.', 'URL', 'Prod', 'Ex.'].freeze

    def run
      exception_ids = fetch_exception_ids

      raw_advisories = scan_for_cves

      # We need to deduplicate advisories with identical ids -
      # yarn audit for instance can yield many copies of the same advisory
      # (for different versions of the same package) but we only care about
      # the common information (module name, etc.)

      raw_advisories_by_id = raw_advisories.group_by { |advisory| advisory.fetch(:id).to_s }

      advisories = raw_advisories_by_id.map do |id, raw_advisories_for_id|
        advisory = raw_advisories_for_id.first

        module_name = advisory.fetch(:module_name)
        title = advisory.fetch(:title)
        severity = advisory.fetch(:severity)
        url = advisory.fetch(:url)
        excepted = exception_ids.include?(id)

        # Each advisory corresponds to some instance of the vulnerable
        # package, which may exist as in multiple nodes of the dependency
        # tree. advisory[:findings] is an array of objects looking roughly
        # like:
        # [
        #   { "version": "1.0.5", ..., "dev": false },
        #   { "version": "1.0.5", ..., "dev": true }
        # ]
        # where each element records an instance of the vulnerable package
        # in the dependency tree. If, for some advisory and for some finding
        # on that advisory, dev is false, then there exists a vulnerable version
        # of the module in the prod dependency tree

        # For all advisories,
        prod = raw_advisories_for_id.any? do |raw_advisory|
          # any there there any instances in the prod dependency tree?
          raw_advisory.fetch(:findings).any? { |finding| !finding.fetch(:dev, false) }
        end

        Advisory.new(id, module_name, title, severity, url, prod, excepted)
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

      prod_advisory_ids = prod_advisories.map(&:id).sort_by(&:to_i)
      dev_advisory_ids = dev_advisories.map(&:id).sort_by(&:to_i)
      unex_prod_advisory_ids = unex_prod_advisories.map(&:id).sort_by(&:to_i)
      prod_exception_ids = prod_exception_ids.sort_by(&:to_i)
      dev_exception_ids = dev_exception_ids.sort_by(&:to_i)
      useless_exception_ids = useless_exception_ids.sort_by(&:to_i)

      # The _id suffix isn't super interesting information from the perspective of an
      # external consumer just drop it
      report_info(:prod_advisories, prod_advisory_ids)
      report_info(:dev_advisories, dev_advisory_ids)
      report_info(:unexcepted_prod_advisories, unex_prod_advisory_ids)
      report_info(:exceptions, useful_exception_ids)
      report_info(:prod_exceptions, prod_exception_ids)
      report_info(:dev_exceptions, dev_exception_ids)
      report_info(:useless_exceptions, useless_exception_ids)

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

      unex_prod_advisories.empty? ? report_success : report_failure
    end

    def should_run?
      raise NoMethodError, 'implement in subclass'
    end

    private

    # This must return an array of the standard advisory info hashes.
    def scan_for_cves
      raise NoMethodError, 'implement in subclass'
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
