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
        shell_return = run_shell('brakeman #{config_options}-f json', env: { "CI" => "true" })

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

    private
    # Taken from https://brakemanscanner.org/docs/options/ 
    def config_options
      build_options(
        prefix: '-',
        suffix: ' ',
        between: ' ',
        args: {
          c: :file, 
          A: :flag, 
          n: :flag, 
          p: :file, 
          q: :flag, 
          '3': :flag, 
          '4': :flag, 
          'no-assume-routes': {type: :flag, prefix: '--'},
          'escape-html': {type: :flag, prefix: '--'},
          faster: {type: :flag, prefix: '--'},
          'no-branching': {type: :flag, prefix: '--'},
          'branch-limit': /^\d+$/,
          'skip-files': :list_file,
          'only-files': :list_file,
          'skip-libs': {type: :flag, prefix: '--'},
          test: :list,
          except: :list,
          i: :file,
          'ignore-model-output': {type: :flag, prefix: '--'},
          'ignore-protected': {type: :flag, prefix: '--'},
          'report-direct': {type: :flag, prefix: '--'},
          'safe-methods': :list, 
          'url-safe-methods': :list,
          w: {
            prefix: '-',
            between: '', #essentially can only be -w1, -w2, -w3
            type: :string,
            regex: /\A1|2|3\z/i,
          },
        }
      )

      options
    end

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

    # flag options taken from https://brakemanscanner.org/docs/options/
    def config_options
      options = ''

      # path/to/rails/app
      # must be an app dir
      options.concat(create_list_file_option('path')) if @config.key?('path')

      options
    end

    def create_file_option(keyword)
      return '' unless validate_file_option(keyword)

      "--#{keyword} #{Shellwords.escape(@config.fetch(keyword))} "
    end
  end
end
