require 'json'
require 'salus/scanners/node_audit'

# Yarn Audit scanner integration. Flags known malicious or vulnerable
# dependencies in javascript projects that are packaged with yarn.
# https://yarnpkg.com/en/docs/cli/audit

module Salus::Scanners
  class YarnAudit < NodeAudit
    AUDIT_COMMAND = 'yarn audit --json'.freeze

    def should_run?
      @repository.yarn_lock_present?
    end

    private

    def scan_deps
      dep_types = @config.fetch('exclude_groups', [])

      return '' if dep_types.empty?

      if dep_types.include?('devDependencies') &&
          dep_types.include?('dependencies') &&
          dep_types.include?('optionalDependencies')
        report_error("No dependencies were scanned!")
        return ''
      elsif dep_types.include?('devDependencies') && dep_types.include?('dependencies')
        report_warn(:scanner_misconfiguration, "Scanning only optionalDependencies!")
      end

      command = ' --groups '
      command << 'dependencies ' unless dep_types.include?('dependencies')
      command << 'devDependencies ' unless dep_types.include?('devDependencies')
      command << 'optionalDependencies ' unless dep_types.include?('optionalDependencies')
    end

    def scan_for_cves
      # Yarn gives us a new-line separated list of JSON blobs.
      # But the last JSON blob is a summary that we can discard.
      # We must also pluck out only the standard advisory hashes.
      command = "#{AUDIT_COMMAND} #{scan_deps}"
      command_output = run_shell(command)

      report_stdout(command_output.stdout)

      command_output.stdout.split("\n")[0..-2].map do |raw_advisory|
        advisory_hash = JSON.parse(raw_advisory, symbolize_names: true)
        advisory_hash[:data][:advisory]
      end
    end
  end
end
