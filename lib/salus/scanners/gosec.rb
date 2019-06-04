require 'salus/scanners/base'
require 'json'
# Gosec scanner check Go for insecure coding patters.
# https://github.com/securego/gosec

module Salus::Scanners
  class Gosec < Base
    def run
      # Shell Instructions:
      #   - -fmt=json for JSON output
      #   - gosec can scan go modules as of 2.0.0.
      shell_return = run_shell("gosec -fmt=json #{@repository.path_to_repo}")

      shell_return_json = JSON.parse(shell_return.stdout)
      lines_scanned = shell_return_json['Stats']['lines']  # number of lines scanned
      golang_errors = shell_return_json['Golang errors']   # a hash of compile errors
      found_issues = shell_return_json['Issues']            # a list of found issues

      # Gosec's Logging Behavior:
      #   - no vulns found - status 0, logs to STDERR and STDOUT
      #   - vulns found    - status 1, logs to STDERR and STDOUT
      #   - build error    - status 1, logs to STDERR only
      return report_success if shell_return.success? && lines_scanned > 0

      report_failure
      if shell_return.status == 1 && (golang_errors.size > 0 || found_issues.size > 0)
        report_stdout(shell_return.stdout)
        log(shell_return.stdout)
      elsif lines_scanned == 0
        report_error(
          "0 lines of code were scanned",
          status: shell_return.status
        )
        report_stderr(shell_return.stderr)
      else
        report_error(
          "gosec exited with build error: #{shell_return.stderr}",
          status: shell_return.status
        )
        report_stderr(shell_return.stderr)
      end
    end

    def should_run?
      # Check go filetypes that tend to be present at top level directory.
      @repository.dep_lock_present? ||
        @repository.go_mod_present? ||
        @repository.go_sum_present? ||
        go_file?
    end

    def go_file?
      !Dir.glob("#{@repository.path_to_repo}/*.go").first.nil?
    end
  end
end
