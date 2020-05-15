require 'bundler'
require 'salus/scanners/base'

# Bandit scanner to check for Python vulns.
# https://github.com/presidentbeef/brakeman

module Salus::Scanners
  class Bandit < Base
    def run
      Dir.chdir(@repository.path_to_repo) do
        # bandit compiled with python3
        copts = config_options
        shell_return = run_shell("bandit #{copts} -r -f json .")

        # if python3 couldn't parse files, then try bandit compiled with python2
        if !shell_return.stdout.empty?
          errs = JSON.parse(shell_return.stdout)['errors']
          if errs.any? { |ei| ei['reason'] == 'syntax error while parsing AST from file' }
            shell_return = run_shell("bandit2 #{copts} -r -f json .")
          end
        end

        # From the Bandit docs:
        #
        # Bandit has the following behavior that we will track:
        #   - no vulns found           - exit 0 and log to STDOUT
        #   - vuln found               - exit 1 and log to STDOUT
        #   - bandit internal error    - exit 2 and log to STDERR

        if shell_return.success?
          errs = JSON.parse(shell_return.stdout)['errors']
          if !errs.empty?
            report_error(errs, status: shell_return.status)
            report_stderr(errs)
            return report_failure
          elsif JSON.parse(shell_return.stdout)['metrics']['_totals']['loc'].zero?
            report_error(
              '0 lines of code were scanned',
              status: shell_return.status
            )
            report_stderr(shell_return.stderr)
            return report_failure
          else
            return report_success
          end
        end

        if shell_return.status == 1
          report_failure
          report_stdout(shell_return.stdout)
          log(shell_return.stdout)
        else
          report_error(
            "bandit exited with an unexpected exit status, #{shell_return.stderr}",
            status: shell_return.status
          )
          report_stderr(shell_return.stderr)
        end
      end
    end

    def should_run?
      @repository.requirements_txt_present? || @repository.setup_cfg_present?
    end

    def config_options
      # config options taken from https://pypi.org/project/bandit/

      string_to_flag_map = {
        'level' => { 'LOW' => 'l', 'MEDIUM' => 'll', 'HIGH' => 'lll',
                     'low' => 'l', 'medium' => 'll', 'high' => 'lll' },
        'confidence' => { 'LOW' => 'i', 'MEDIUM' => 'ii', 'HIGH' => 'iii',
                          'low' => 'i', 'medium' => 'ii', 'high' => 'iii' }
      }
      args = build_flag_args_from_string(string_to_flag_map)
      args.merge!(aggregate: { type: :string, keyword: 'a' },
                  configfile: { type: :file, keyword: 'c' },
                  profile: { type: :string, keyword: 'p' },
                  tests: { type: :list, keyword: 't' },
                  skip: { type: :list, keyword: 's' },
                  baseline: { type: :file, keyword: 'b' },
                  ini: { type: :file, prefix: '--' },
                  'ignore-nosec': { type: :flag, prefix: '--' },
                  exclude: { type: :list_file, keyword: 'x' })
      build_options(
        prefix: '-',
        suffix: ' ',
        separator: ' ',
        args: args
      )
    end
  end
end
