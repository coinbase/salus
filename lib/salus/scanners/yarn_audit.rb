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

    def scan_for_cves
      # Yarn gives us a new-line separated list of JSON blobs.
      # But the last JSON blob is a summary that we can discard.
      # We must also pluck out only the standard advisory hashes.
      command_output = run_shell(AUDIT_COMMAND)

      report_stdout(command_output.stdout)

      command_output.stdout.split("\n")[0..-2].map do |raw_advisory|
        advisory_hash = JSON.parse(raw_advisory, symbolize_names: true)
        advisory_hash[:data][:advisory]
      end
    end
  end
end
