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
      shell_return = run_shell('trufflehog --version')
      shell_return.stdout&.split&.dig(1)
      # stdout looks like "trufflehog 3.18.0\n"
    end

    def self.supported_languages
      ['*']
    end

    def command
      "trufflehog filesystem --directory=. --only-verified --json"
    end

    def run
      #    shell_return = run_shell(command, chdir: @repository.path_to_repo)

      shell_return = run_shell(command, chdir: '/home/repo')
      puts "SHELLRETURNTEST #{shell_return.inspect}"
      exit

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
