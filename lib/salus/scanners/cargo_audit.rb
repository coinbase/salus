require 'json'
# Rust Cargo Audit scanner integration. Flags known malicious or vulnerable
# dependencies in rust projects that are packaged with cargo.
# https://github.com/RustSec/cargo-audit

module Salus::Scanners
  class CargoAudit < Base
    def should_run?
      @repository.cargo_lock_present?
    end

    def run
      Dir.chdir(@repository.path_to_repo) do
        shell_return = run_shell(command)

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
          # shell_return.stdout will be JSON of the discovered vulnerabilities
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

    protected

    def command
      # USAGE:
      #     cargo-audit <OPTIONS>

      # FLAGS:
      #     -h, --help                output help information and exit
      #     --version                 output version and exit
      #     -c, --color COLOR         color configuration: always, never (default: auto)
      #     -d, --db DB               advisory database git repo path
      #     -D, --deny-warnings       exit with an error if any warning advisories are found
      #     -f, --file FILE           Cargo lockfile to inspect
      #     --ignore                  ADVISORY_ID Advisory id to ignore
      #     -n, --no-fetch            do not perform a git fetch on the advisory DB
      #     --stale                   allow stale database
      #     --target-arch TARGET-ARCH filter vulnerabilities by CPU (default: no filter)
      #     --target-os TARGET-OS     filter vulnerabilities by OS (default: no filter)
      #     -u, --url URL             URL for advisory database git repo
      #     -q, --quiet               Avoid printing unnecessary information
      #     --json                    Output report in JSON format
      #     --no-local-crates         Vulnerability querying does not consider local crates

      opts = ["--json"]  # return vulnerabilities in an easily digestible manner (JSON)
      opts << "-c never" # to prevent color chars in stderr upon failure
      opts += fetch_exception_ids.map { |id| "--ignore #{id}" }

      "cargo audit #{opts.join(' ')}"
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
  end
end
