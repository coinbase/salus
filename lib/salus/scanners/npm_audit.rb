require 'json'
require 'salus/scanners/base'

# NPM Audit scanner - looks for CVEs in node dependencies.

module Salus::Scanners
  class NPMAudit < Base
    ADVISORY_URL_REGEX = %r{^https://nodesecurity.io/advisories/(\d+)$}

    def run
      exceptions = @config.fetch('exceptions', [])
      created_package_lock = false

      if !@repository.package_lock_json_present?
        Dir.chdir(@repository.path_to_repo) do
          report_info(
            :package_lock_missing,
            'No package.lock file was found, so we generated one for you. As long as '\
              'you use yarn, this should be fine. If not, please check in a package-lock.json '\
              'file into your source control.'
          )
          run_shell('npm i --package-lock-only')
          created_package_lock = true
        end
      end

      shell_return = nil
      Dir.chdir(@repository.path_to_repo) { shell_return = run_shell('npm audit --json') }

      return report_success if shell_return.success?

      # Parse output
      npm_audit_report = JSON.parse(shell_return.stdout, symbolize_names: true)

      # Report scan output
      report_info(:npm_audit_output, npm_audit_report)

      # FIXME(as3richa): emit some sort of warning or logline
      # for exceptions that don't conform to the spec
      exceptions = exceptions.select do |exception|
        exception.is_a?(Hash) &&
          exception.keys.sort == %w[advisory_id changed_by notes]
      end

      report_info(:exceptions, exceptions)

      exception_ids = exceptions.map { |exception| exception['advisory_id'] }
      active_vuln_ids = npm_audit_report[:advisories].keys.map(&:to_s) - exception_ids

      report_info(:vulnerabilities, active_vuln_ids)

      active_vuln_ids.empty? ? report_success : report_failure
    ensure
      # Cleanup, mostly for local dev since we run in Docker normally
      File.delete("#{@repository.path_to_repo}/package-lock.json") if created_package_lock
    end

    def should_run?
      @repository.package_json_present? ||
        @repository.package_lock_json_present? ||
        @repository.yarn_lock_present?
    end
  end
end
