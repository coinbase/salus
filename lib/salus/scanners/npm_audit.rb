require 'json'
require 'stringio'
require_relative 'base'
require_relative '../npm_audit_wrapper'

# NPM Audit scanner integration. Replaces the NSP module and flags known malicious or vulnerable
# dependencies in javascript projects.
# https://medium.com/npm-inc/npm-acquires-lift-security-258e257ef639

module Salus::Scanners
  class NPMAudit < Base
    def run
      sanity_check_exceptions

      exceptions =
        @config.fetch('exceptions', [])
          .map { |ex| ex['advisory_id']&.to_s }
          .compact

      stdout = StringIO.new

      auditor =
        Salus::NpmAuditWrapper.new(
          stream: stdout,
          exceptions: exceptions,
          path: @repository.path_to_repo
        )

      okay = auditor.run!

      report_stdout(stdout.string)

      if okay
        report_success
      else
        report_failure
      end
    end

    def sanity_check_exceptions
      @config['exceptions']&.each do |ex|
        if !ex.is_a?(Hash) || ex.keys.sort != %w[advisory_id changed_by notes]
          report_error(
            "malformed exception: #{ex.inspect}; " \
            'expected a hash with keys `advisory_id`, `changed_by`, `notes`'
          )
          next
        end
      end
    end

    def should_run?
      @repository.package_json_present? ||
        @repository.package_lock_json_present? ||
        @repository.yarn_lock_present?
    end
  end
end
