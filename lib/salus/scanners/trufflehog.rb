require 'json'
require 'salus/scanners/base'

# Trufflehog scanner integration. Flags secrect present in the repo.
# https://github.com/trufflesecurity/trufflehog


# TOOD Create a SARIF adapter in lib/sarif
module Salus::Scanners
  class Trufflehog < Base

    def should_run?
      true
    end

    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def version
       shell_return = run_shell('docker run --platform linux/arm64 -v trufflesecurity/trufflehog:latest --version')                                            
      shell_return.stdout&.split&.dig(1)
      # stdout looks like "trufflehog 3.18.0\n"
    end

    def self.supported_languages
      ['*']
    end

    def command
      # Usage: TruffleHog [<flags>] <command> [<args> ...]
      # 
      # TruffleHog is a tool for finding credentials.
      # 
      # Flags:
      #     --help                     Show context-sensitive help (also try --help-long and --help-man).
      #      --debug                    Run in debug mode.
      #      --trace                    Run in trace mode.
      #  -j, --json                     Output in JSON format.
      #      --json-legacy              Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.
      #      --concurrency=4            Number of concurrent workers.
      #      --no-verification          Don't verify the results.
      #      --only-verified            Only output verified results.
      #      --filter-unverified        Only output first unverified result per chunk per detector if there are more than one results.
      #      --print-avg-detector-time  Print the average time spent on each detector.
      #      --no-update                Don't check for updates.
      #      --fail                     Exit with code 183 if results are found.
      #     --version                  Show application version.
      #
      # Commands:
      # help [<command>...]
      #    Show help.
      #
      #  git [<flags>] <uri>
      #    Find credentials in git repositories.
      #
      #  github [<flags>]
      #    Find credentials in GitHub repositories.
      #
      #  gitlab --token=TOKEN [<flags>]
      #    Find credentials in GitLab repositories.

      #  filesystem --directory=DIRECTORY
      #    Find credentials in a filesystem.

      #  s3 [<flags>]
      #    Find credentials in S3 buckets.

      #  syslog [<flags>]
      #    Scan syslog

      "docker run --platform linux/arm64 -v #{File.expand_path(@repository.path_to_repo)}:/pwd trufflesecurity/trufflehog:latest filesystem --json --directory=./ --no-verification"
    end

    def run
      shell_return = run_shell(command, chdir: @repository.path_to_repo)

      binding.pry

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
  end
end
