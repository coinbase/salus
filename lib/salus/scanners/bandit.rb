require 'salus/scanners/base'

# Bandit scanner to check for Python vulns.
# https://pypi.org/project/bandit/

module Salus::Scanners
  class Bandit < Base
    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def run
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

    def should_run?
      has_py_files = (@repository.py_files_present? != false)
      (@repository.requirements_txt_present? || @repository.setup_cfg_present?) &&
        has_py_files
    end

    def version
      shell_return = run_shell('bandit --version')
      # stdout looks like "bandit 1.6.2\n  ..."
      shell_return.stdout&.split("\n")&.dig(0)&.split&.dig(1)
    end

    def self.supported_languages
      ['python']
    end

    def exception_skips
      skips = @config.fetch('skip', [])
      exception_ids = fetch_exception_ids
      (skips + exception_ids).uniq
    end

    # Taken from https://pypi.org/project/bandit/#usage
    def config_options
      string_to_flag_map = {
        'level' => { 'LOW' => 'l', 'MEDIUM' => 'll', 'HIGH' => 'lll' },
        'confidence' => { 'LOW' => 'i', 'MEDIUM' => 'ii', 'HIGH' => 'iii' }
      }
      args = build_flag_args_from_string(string_to_flag_map)
      args.merge!(aggregate: { type: :string, keyword: 'a', regex: /\Afile|vuln\z/i },
                  configfile: { type: :file, keyword: 'c' },
                  profile: { type: :string, keyword: 'p' },
                  tests: { type: :list, keyword: 't', regex: /\AB\d{3}\z/i },
                  skip: { type: :list, keyword: 's', regex: /\AB\d{3}\z/i },
                  baseline: { type: :file, keyword: 'b' },
                  ini: { type: :file, prefix: '--' },
                  'ignore-nosec': { type: :flag, prefix: '--' },
                  exclude: { type: :list_file, keyword: 'x' })

      # To allow backwards compatability we are creating a composite
      # of the skips and exceptions blocks.  Eventually we should retire skips
      # in favor of the new exception support
      skips = exception_skips
      overrides = skips.empty? ? {} : { 'skip' => skips }

      build_options(
        prefix: '-',
        suffix: ' ',
        separator: ' ',
        args: args,
        config_overrides: overrides
      )
    end
  end
end
