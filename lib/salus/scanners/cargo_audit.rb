require 'json'
require 'salus/scanners/base'

# Rust Cargo Audit scanner integration. Flags known malicious or vulnerable
# dependencies in rust projects that are packaged with cargo.
# https://github.com/RustSec/cargo-audit

module Salus::Scanners
  class CargoAudit < Base
    include Salus::Formatting

    ELEVATE_WARNINGS = 'elevate_warnings'.freeze

    def should_run?
      @repository.cargo_lock_present?
    end

    def self.scanner_type
      Salus::ScannerTypes::DEPENDENCY
    end

    def run
      shell_return = run_shell(command, chdir: @repository.path_to_repo)

      # Cargo Audit has the following behavior:
      #
      # - vulnerability NOT found:
      #   - status: 0
      #   - stderr: ""
      #   - stdout: JSON Milestones, counts of crates scanned
      #
      # - vulnerability found:
      #   - status: 1
      #   - stderr: ""
      #   - stdout: JSON detail of the vulnerability
      #
      # - warning found:
      #   - status: 0
      #   - stderr: ""
      #   - stdout: JSON detail of the warning
      #
      # - Error running audit:
      #   - status: 1
      #   - stderr: String with details on the error preventing the run (not JSON)
      #   - stdout: ""

      return report_success if shell_return.success? && !has_vulnerabilities?(shell_return.stdout)

      report_failure

      if shell_return.stderr.empty?
        # shell_return.stdout will be JSON of the discovered vulnerabilities
        report_stdout(shell_return.stdout)
        log(prettify_json_string(shell_return.stdout))
      else
        report_error(
          "cargo exited with an unexpected exit status",
          status: shell_return.status
        )
        report_stderr(shell_return.stderr)
      end
    end

    def version
      shell_return = run_shell('cargo audit --version')
      # stdout looks like "cargo-audit 0.12.0\n"
      shell_return.stdout&.split&.dig(1)
    end

    def self.supported_languages
      ['rust']
    end

    protected

    def has_vulnerabilities?(json_string)
      json = JSON.parse(json_string)
      # We will treat warnings as vulnerabilities
      json["vulnerabilities"]["found"] || (elevate_warnings? && json["warnings"].present?)
    end

    def elevate_warnings?
      # default to elevating warnings if the config lacks an entry
      @config.key?(ELEVATE_WARNINGS) ? @config[ELEVATE_WARNINGS] : true
    end

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
      # Note that -D is not yet supported with --json

      opts = ["--json"] # return vulnerabilities in an easily digestible manner (JSON)
      opts << "-c never" # to prevent color chars in stderr upon failure
      opts += fetch_exception_ids.map { |id| "--ignore #{id}" }

      "cargo audit #{opts.join(' ')}"
    end
  end
end
