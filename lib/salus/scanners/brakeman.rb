require 'bundler'
require 'salus/scanners/base'
require 'tempfile'
# Brakeman scanner to check for Rails web app vulns.
# https://github.com/presidentbeef/brakeman

module Salus::Scanners
  class Brakeman < Base
    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def run
      # Use JSON output since that will be the best for an API to receive and parse.
      # We need CI=true envar to ensure brakeman doesn't use an interactive display
      # for the report that it outputs.
      shell_return = run_with_exceptions_applied(@repository.path_to_repo)
      # From the Brakeman website:
      #   Note all Brakeman output except reports are sent to stderr,
      #   making it simple to redirect stdout to a file and just get the report.
      #
      # Brakeman has the following behavior that we will track:
      #   - no vulns found - exit 0 and log to STDOUT
      #   - vulns found    - exit 3 (warning) or 7 (error) and log to STDOUT
      #   - exception      - exit 1 and log to STDERR
      # Warnings_Found_Exit_Code = 3

      # Exit code returned when no Rails application is detected
      # No_App_Found_Exit_Code = 4

      # Exit code returned when brakeman was outdated
      # Not_Latest_Version_Exit_Code = 5

      # Exit code returned when user requests non-existent checks
      # Missing_Checks_Exit_Code = 6

      # Exit code returned when errors were found and the --exit-on-error
      # option is set
      # Errors_Found_Exit_Code = 7

      # Exit code returned when an ignored warning has no note and
      # --ensure-ignore-notes is set
      # Empty_Ignore_Note_Exit_Code = 8

      return report_success if shell_return&.success?

      if shell_return&.status == 3 || shell_return&.status == 7
        report_failure
        report_stdout(shell_return.stdout)
        log(shell_return.stdout)
      else
        report_error(
          "brakeman exited with an unexpected exit status",
          status: shell_return&.status
        )
        report_stderr(shell_return&.stderr)
      end
    end

    def should_run?
      @repository.gemfile_present? && has_rails_gem? && has_app_dir?
    end

    def version
      Gem.loaded_specs["brakeman"].version.to_s
    end

    def self.supported_languages
      ['ruby']
    end

    def run_without_exceptions_applied(path)
      run_shell("brakeman #{config_options} -f json", env: { "CI" => "true" }, chdir: path)
    end

    def run_with_exceptions_applied(path)
      return run_without_exceptions_applied(path) unless needs_temporary_ignore?

      # create a temporary file combining ignore file entries with any user supplied
      # entires if exceptions hash is being used.
      # We could look at using IO.popen to create an unnamed unidirectional pipe if
      # we find the tempfile inelegant
      begin
        Tempfile.create('salus') do |f|
          f.write(merged_ignore_file_contents)
          f.close

          opts = if user_supplied_ignore?
                   config_options.gsub(@config['ignore'], f.path)
                 else
                   config_options + " -i #{f.path} "
                 end
          run_shell("brakeman #{opts} -f json", env: { "CI" => "true" }, chdir: path)
        end
      rescue Errno::EROFS
        report_error("Read only filesystem, unable to apply exceptions")
        run_without_exceptions_applied(path)
      end
    end

    def merged_ignore_file_contents
      # combine the ignore file and the exception config
      ignores = ignore_list
      exceptions = exception_list.map do |ex|
        { 'fingerprint' => ex['advisory_id'],
          'expiration' => ex['expiration'],
          'notes' => ex['notes'] }
      end
      ignore = (ignores + exceptions).uniq.select { |ig| Salus::ConfigException.new(ig).active? }

      JSON.generate({ 'ignored_warnings' => ignore })
    end

    def ignore_list
      return [] unless user_supplied_ignore?

      data = JSON.parse(File.read(@config['ignore']))
      return [] unless data.key?('ignored_warnings')

      data['ignored_warnings']
    end

    def exception_list
      return [] unless user_supplied_exceptions?

      @config['exceptions']
    end

    def needs_temporary_ignore?
      # If the user is using exceptions OR expirations in the ignore
      # file we will need to make a temporary ignore
      user_supplied_ignore_expirations? || user_supplied_exceptions?
    end

    def user_supplied_ignore_expirations?
      ignore_list.each do |item|
        return true if item.key?('expiration')
      end
      false
    end

    def user_supplied_ignore?
      @config.key?("ignore")
    end

    def user_supplied_exceptions?
      @config.key?("exceptions")
    end

    # Taken from https://brakemanscanner.org/docs/options/
    def config_options
      flag_with_two_dashes = { type: :flag, prefix: '--' }
      list_with_two_dashes = { type: :list, prefix: '--' }
      file_list_with_two_dashes = { type: :list_file, prefix: '--' }

      build_options(
        prefix: '-',
        suffix: ' ',
        separator: ' ',
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
          path: { type: :file, prefix: '--' },
          'no-informational': {
            type: :flag,
            keyword: 'q'
          },
          'rails3': {
            type: :flag,
            keyword: '3'
          },
          'rails4': {
            type: :flag,
            keyword: '4'
          },
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
            separator: '', # essentially can only be -w1, -w2, -w3
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
        (@config.key?('path') && validate_file_option('path', @config['path']) &&
          @config.fetch('path').split('/')[-1].contains('app'))
    end
  end
end
