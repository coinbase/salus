require "salus/scanners/base"
require "json"

# Gitleaks scanner integration. Detects hardcoded secrets like passwords,
# api keys, and tokens in git repos.
# https://github.com/zricethezav/gitleaks

module Salus::Scanners
  class Gitleaks < Base
    def run
      Dir.chdir(@repository.path_to_repo) do
        copts = config_options
        shell_return = run_shell(
          'gitleaks '\
          '--path . '\
          '--format sarif '\
          '--report /dev/stdout '\
          '--leaks-exit-code 0 ' +
          copts
        )

        report_stderr(shell_return.stderr)

        # A non-zero exit code is definitely an error
        if !shell_return.success?
          report_stdout(shell_return.stdout)
          report_error("Call to gitleaks failed", {
                         status: shell_return.status,
                         stderr: shell_return.stderr.split("\n").last
                       })
          return report_failure
        end

        # Otherwise handle the SARIF output
        # As of 2.7.1, no report is generated if no secrets were found
        sarif = if shell_return.stdout.empty?
                  {
                    'runs' => []
                  }
                else
                  JSON.parse(shell_return.stdout)
                end

        report_runs(sarif['runs'])
      end
    end

    def should_run?
      true # Always run on the provided folder
    end

    def version
      shell_return = run_shell('gitleaks --version')
      # stdout looks like "7.2.0\n"
      shell_return.stdout&.strip&.slice(1..)
    end

    # Taken from https://github.com/zricethezav/gitleaks#usage-and-options
    def config_options
      build_options(
        prefix: '--',
        suffix: ' ',
        separator: ' ',
        args: {
          'config-path': :file,
          'repo-config-path': :file,
          threads: :int,
          unstaged: :flag,
          branch: :string,
          redact: :flag,
          'no-git': :flag,
          'files-at-commit': :string,
          commit: :string,
          commits: { type: :list, join_by: ',' },
          'commits-file': :file,
          'commit-from': :string,
          'commit-to': :string,
          'commit-since': :string,
          'commit-until': :string,
          depth: :int
        }
      )
    end

    # Report SARIF output from the scanner.
    def report_runs(runs)
      # If the results object had findings (workaround for https://github.com/zricethezav/gitleaks/pull/530)
      if runs.any? { |run| !run['results'].nil? && !run['results'].empty? }
        @report.fail
      else
        @report.pass
      end

      all_hits = []
      runs.each do |run|
        run['results']&.each do |result|
          loc = result['locations'].first['physicalLocation']
          all_hits << {
            msg: result['message']['text'],
            file: loc['artifactLocation']['uri'],
            line: loc['region']['startLine'],
            hit: loc['region']['snippet']['text']
          }
        end
      end
      report_info(:hits, all_hits)
    end
  end
end
