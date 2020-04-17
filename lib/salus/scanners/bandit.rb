require 'bundler'
require 'salus/scanners/base'

# Bandit scanner to check for Python vulns.
# https://github.com/presidentbeef/brakeman

module Salus::Scanners
  class Bandit < Base
    def run
      Dir.chdir(@repository.path_to_repo) do
        shell_return = run_shell('bandit -r -ii -f json -a file -x tests .')

        # From the Bandit docs:
        #
        # Bandit has the following behavior that we will track:
        #   - no vulns found           - exit 0 and log to STDOUT
        #   - vuln found               - exit 1 and log to STDOUT
        #   - bandit internal error    - exit 2 and log to STDERR

        return report_success if shell_return.success?

        if shell_return.status == 1
          report_failure
          report_stdout(shell_return.stdout)
          log(shell_return.stdout)
        else
          report_error(
            "bandit exited with an unexpected exit status",
            status: shell_return.status
          )
          report_stderr(shell_return.stderr)
        end
      end
    end

    def should_run?
      @repository.requirements_txt_present? || @repository.setup_cfg_present?
    end
  end
end
