require 'salus/scanners/base'
# Gosec scanner check Go for insecure coding patters.
# https://github.com/securego/gosec

module Salus::Scanners
  class Gosec < Base
    def run
      # Shell Instructions:
      #   - -fmt=json for JSON output
      #   - gosec only successfully scans repos within $GOPATH, we force the
      #     go path reference via symlink within Dockerfile & Dockerfile.tests
      if ENV['RUNNING_SALUS_TESTS'] == "true"
        shell_return = run_shell("gosec -fmt=json /go/src/repo/#{@repository.path_to_repo}")
      else
        shell_return = run_shell("gosec -fmt=json /go/src/repo")
      end

      # Gosec's Logging Behavior:
      #   - no vulns found - status 0, logs to STDERR and STDOUT
      #   - vulns found    - status 1, logs to STDERR and STDOUT
      #   - build error    - status 1, logs to STDERR only
      return report_success if shell_return.success?

      if shell_return.status == 1 && !shell_return.stdout.blank? && shell_return.stderr
        report_failure
        report_stdout(shell_return.stdout)
        log(shell_return.stdout)
      else
        report_failure
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
      !(Dir.glob("#{@repository.path_to_repo}/*.go").first.nil?)
    end
  end
end
