require 'json'
# Rust Audit scanner integration. Flags known malicious or vulnerable
# dependencies in rust projects that are packaged with cargo.
# https://github.com/RustSec/cargo-audit

module Salus::Scanners
  class RustAudit < Base
    def should_run?
      @repository.cargo_lock_present?
    end

    def run
      Dir.chdir(@repository.path_to_repo) do
        # --json to return vulnerabilities in an easily digestible manner
        # -c never to prevent color chars in stderr upon failure

        shell_return = run_shell("cargo audit -c never --json")

        # Cargo Audit has the following behavior:
        #
        # - vulnerability NOT found:
        #   - status: 0
        #   - stderr: ""
        #   - stdout: Milestones, counts of crates scanned
        #
        # - vulnerability found:
        #   - status: 1
        #   - stderr: ""
        #   - stdout: JSON detail of the vulnerability
        #
        # - Error running audit:
        #   - status: 1
        #   - stderr: String with details on the error prenting the run (not JSON)
        #   - stdout: ""

        return report_success if shell_return.success?

        if shell_return.stderr.empty?
          report_failure
          report_stdout(shell_return.stdout)
          log(shell_return.stdout)
        else
          report_error(
            "cargo exited with an unexpected exit status",
            status: shell_return.status
          )
          report_stderr(shell_return.stderr)
        end
      end
    end
  end
end
