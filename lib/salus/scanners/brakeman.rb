require 'bundler'
require 'salus/scanners/base'

# Brakeman scanner to check for Rails web app vulns.
# https://github.com/presidentbeef/brakeman

module Salus::Scanners
  class Brakeman < Base
    def run
      Dir.chdir(@repository.path_to_repo) do
        # Use JSON output since that will be the best for an API to receive and parse.
        # We need CI=true envar to ensure brakeman doesn't use an interactive display
        # for the report that it outputs.
        shell_return = run_shell("brakeman #{config_options} -f json", env: { "CI" => "true" })

        # From the Brakeman website:
        #   Note all Brakeman output except reports are sent to stderr,
        #   making it simple to redirect stdout to a file and just get the report.
        #
        # Brakeman has the following behavior that we will track:
        #   - no vulns found - exit 0 and log to STDOUT
        #   - vulns found    - exit 3 (warning) or 7 (error) and log to STDOUT
        #   - exception      - exit 1 and log to STDERR

        return report_success if shell_return.success?

        if shell_return.status == 3 || shell_return.status == 7
          report_failure
          report_stdout(shell_return.stdout)
          log(shell_return.stdout)
        else
          report_error(
            "brakeman exited with an unexpected exit status",
            status: shell_return.status
          )
          report_stderr(shell_return.stderr)
        end
      end
    end

    def should_run?
      @repository.gemfile_present? && has_rails_gem? && has_app_dir?
    end

    # Taken from https://brakemanscanner.org/docs/options/
    def config_options
      flag_with_two_dashes = { type: :flag, prefix: '--' }
      list_with_two_dashes = { type: :list, prefix: '--' }
      file_list_with_two_dashes = { type: :list_file, prefix: '--' }
      build_options(
        prefix: '-',
        suffix: ' ',
        between: ' ',
        args: {
          config: {
            type: :file,
            keyword: 'c'
          },
          all: {
            type: :flag,
            keyword: 'A'
          },
          'no-threads': {
            type: :flag,
            keyword: 'n'
          },
          path: file_list_with_two_dashes,
          q: {
            type: :flag,
            keyword: 'q'
          },
          '3': :flag,
          '4': :flag,
          'no-assume-routes': flag_with_two_dashes,
          'escape-html': flag_with_two_dashes,
          faster: flag_with_two_dashes,
          'no-branching': flag_with_two_dashes,
          'branch-limit': /^\d+$/,
          'skip-files': file_list_with_two_dashes,
          'only-files': file_list_with_two_dashes,
          'skip-libs': flag_with_two_dashes,
          test: list_with_two_dashes,
          except: list_with_two_dashes,
          ignore: {
            type: :file,
            keyword: 'i'
          },
          'ignore-model-output': flag_with_two_dashes,
          'ignore-protected': flag_with_two_dashes,
          'report-direct': flag_with_two_dashes,
          'safe-methods': list_with_two_dashes,
          'url-safe-methods': list_with_two_dashes,
          warning: {
            prefix: '-',
            between: '', # essentially can only be -w1, -w2, -w3
            type: :string,
            regex: /\A1|2|3\z/i,
            keyword: 'w'
          }
        }
      )
    end

    private

    def has_rails_gem?
      gemfile_path = "#{@repository.path_to_repo}/Gemfile"
      gemfile_lock_path = "#{@repository.path_to_repo}/Gemfile.lock"
      Bundler::Definition.build(gemfile_path, gemfile_lock_path, nil)
        .dependencies.map(&:name)
        .include?('rails')
    end

    def has_app_dir?
      Dir.exist?(File.join(@repository.path_to_repo, 'app')) ||
        (@config.key?('path') && validate_file_option('path') &&
          @config.fetch('path').split('/')[-1].contains('app'))
    end

    def create_file_option(keyword)
      return '' unless validate_file_option(keyword)

      "--#{keyword} #{Shellwords.escape(@config.fetch(keyword))} "
    end
  end
end
