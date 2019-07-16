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
      command_output = run_streaming_shell(AUDIT_COMMAND) do |stdout_line, stderr_line, thread|
        if !stdout_line.empty?
          advisory_hash = JSON.parse(stdout_line, symbolize_names: true)
          if advisory_hash[:type] == 'auditAdvisory'
            advisory_hash[:data][:advisory][:findings][0][:paths] = nil
            stdout_line = advisory_hash[:data][:advisory]
          else
            advisory_hash
          end
        else
          stderr_line
        end
      end

      report_stdout(command_output.stdout.map(&:to_s).join("\n"))

      command_output.stdout[0..-2]
    end
  end
end
