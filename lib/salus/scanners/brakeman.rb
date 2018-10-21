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
        shell_return = run_shell('brakeman -f json', env: { "CI" => "true" })

        # From the Brakeman website:
        #   Note all Brakeman output except reports are sent to stderr,
        #   making it simple to redirect stdout to a file and just get the report.
        #
        # Brakeman has the following behavior that we will track:
        #   - no vulns found - exit 0 and log to STDOUT
        #   - vulns found    - exit 3 and log to STDOUT
        #   - exception      - exit 1 and log to STDERR

        if shell_return.success?
          report_success
        elsif shell_return.status == 3
          report_failure
          brakeman_report = JSON.parse(shell_return.stdout)
          report_stdout(shell_return.stdout)
          report_info('brakeman_report', brakeman_report)
        else
          report_info('exit_code', shell_return.status)
          report_error('message' => shell_return.stderr)
          report_stderr(shell_return.stderr)
        end
      end
    end

    def should_run?
      @repository.gemfile_present? && has_rails_gem?
    end

    private

    def has_rails_gem?
      gemfile_path = "#{@repository.path_to_repo}/Gemfile"
      gemfile_lock_path = "#{@repository.path_to_repo}/Gemfile.lock"
      Bundler::Definition.build(gemfile_path, gemfile_lock_path, nil)
        .dependencies.map(&:name)
        .include?('rails')
    end
  end
end
