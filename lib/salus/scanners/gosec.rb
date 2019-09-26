require 'salus/scanners/base'
require 'json'
require 'shellwords'

# Gosec scanner check Go for insecure coding patters.
# https://github.com/securego/gosec

module Salus::Scanners
  class Gosec < Base
    def run
      # Shell Instructions:
      #   - -fmt=json for JSON output
      #   - gosec can scan go modules as of 2.0.0.
      shell_return = Dir.chdir(@repository.path_to_repo) do
        run_shell("gosec #{config_options}-fmt=json ./...")
      end

      # This produces no JSON output so must be checked before parsing stdout
      if shell_return.stdout.blank? && shell_return.stderr.include?('No packages found')
        report_error(
          '0 lines of code were scanned',
          status: shell_return.status
        )
        report_stderr(shell_return.stderr)
        return report_failure
      end

      shell_return_json = JSON.parse(shell_return.stdout)
      lines_scanned = shell_return_json['Stats']['lines']  # number of lines scanned
      golang_errors = shell_return_json['Golang errors']   # a hash of compile errors
      found_issues = shell_return_json['Issues'] # a list of found issues

      # Gosec's Logging Behavior:
      #   - no vulns found - status 0, logs to STDERR and STDOUT
      #   - vulns found    - status 1, logs to STDERR and STDOUT
      #   - build error    - status 1, logs to STDERR only
      return report_success if shell_return.success? && lines_scanned.positive?

      report_failure
      if shell_return.status == 1 && (!golang_errors.empty? || !found_issues.empty?)
        report_stdout(shell_return.stdout)
        log(shell_return.stdout)
      elsif lines_scanned.zero?
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

    # flag options taken from https://github.com/securego/gosec/blob/2.0.0/cmd/gosec/main.go
    def config_options
      options = ''
      # Ignores #nosec comments when set
      options.concat(create_bool_option('nosec')) if @config.key?('nosec')

      # Set an alternative string for #nosec
      options.concat(create_string_option('nosec-tag', /\A\S+\z/)) if @config.key?('nosec-tag')

      # Path to optional config file
      # options.concat(create_file_option('conf')) if @config.key?('conf')

      # Comma separated list of rules IDs to include
      options.concat(create_list_option('include', /\AG\d{3}\z/i)) if @config.key?('include')

      # Comma separated list of rules IDs to exclude
      options.concat(create_list_option('exclude', /\AG\d{3}\z/i)) if @config.key?('exclude')

      # Sort issues by severity
      options.concat(create_bool_option('sort')) if @config.key?('sort')

      # Comma separated list of build tags
      # options.concat(create_list_option('tags', /\A\S*\z/)) if @config.key?('tags')

      # Filter out the issues with a lower severity than the given value.
      # Valid options are: low, medium, high
      lmh_regex = /\Alow|medium|high\z/i
      options.concat(create_string_option('severity', lmh_regex)) if @config.key?('severity')

      # Filter out the issues with a lower confidence than the given value.
      # Valid options are: low, medium, high
      options.concat(create_string_option('confidence', lmh_regex)) if @config.key?('confidence')

      # Do not fail the scanning, even if issues were found
      options.concat(create_bool_option('no-fail')) if @config.key?('no-fail')

      # Scan tests files
      options.concat(create_bool_option('tests')) if @config.key?('tests')

      # exlude the folders from scan
      # can be files or directories
      options.concat(create_list_file_option('exclude-dir')) if @config.key?('exclude-dir')

      options
    end

    def should_run?
      # Check go filetypes that tend to be present at top level directory.
      @repository.dep_lock_present? ||
        @repository.go_mod_present? ||
        @repository.go_sum_present? ||
        go_file?
    end

    def go_file?
      !Dir.glob("#{@repository.path_to_repo}/**/*.go").first.nil?
    end

    private

    def create_bool_option(keyword)
      return '' unless validate_bool_option(keyword)

      "-#{keyword}=#{Shellwords.escape(@config.fetch(keyword))} "
    end

    def create_file_option(keyword)
      return '' unless validate_file_option(keyword)

      "-#{keyword}=#{Shellwords.escape(@config.fetch(keyword))} "
    end

    def create_string_option(keyword, regex)
      return '' unless validate_string_option(keyword, regex)

      "-#{keyword}=#{Shellwords.escape(@config.fetch(keyword))} "
    end

    def create_list_option(keyword, regex)
      return '' unless validate_list_option(keyword, regex)

      "-#{keyword}=#{Shellwords.escape(@config.fetch(keyword).join(','))} "
    end

    def create_list_file_option(keyword)
      file_array = @config.fetch(keyword)
      @config[keyword] = nil

      options = ''
      file_array.each do |file|
        @config[keyword] = file
        options.concat(create_file_option(keyword))
      end
      options
    end
  end
end
