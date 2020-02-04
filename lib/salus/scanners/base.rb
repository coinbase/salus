require 'open3'
require 'salus/scan_report'
require 'salus/shell_result'
require 'shellwords'

module Salus::Scanners
  # Super class for all scanner objects.
  class Base
    class UnhandledExitStatusError < StandardError; end
    class InvalidScannerInvocationError < StandardError; end

    attr_reader :report

    def initialize(repository:, config:)
      @repository = repository
      @config = config
      @report = Salus::ScanReport.new(
        name,
        custom_failure_message: @config['failure_message']
      )
    end

    def name
      self.class.name.sub('Salus::Scanners::', '')
    end

    # The scanning logic or something that calls a scanner.
    def run
      raise NoMethodError
    end

    # Returns TRUE if this scanner is appropriate for this repo, ELSE false.
    def should_run?
      raise NoMethodError
    end

    # Wraps the actual workhorse #run method with some boilerplate:
    # - appends the scan report to the given global salus report
    # - uses the #record method of @report to record the running time of the scan,
    #   and also to pass/fail the scan if #run failed to do so
    # - catches any exceptions, appending them to both the scan report's error
    #   collection and the global salus scan's error collection
    def run!(salus_report:, required:, pass_on_raise:, reraise:)
      salus_report.add_scan_report(@report, required: required)

      begin
        @report.record { run }

        if @report.errors.any?
          pass_on_raise ? @report.pass : @report.fail
        end
      rescue StandardError => e
        error_data = {
          message: "Unhandled exception running #{name}: #{e.class}: #{e}",
          error_class: e.class,
          backtrace: e.backtrace.take(5)
        }

        pass_on_raise ? @report.pass : @report.fail

        # Record the error so that the Salus report captures the issue.
        @report.error(error_data)
        salus_report.error(error_data)

        raise if reraise
      end
    end

    # Runs a command on the terminal.
    def run_shell(command, env: {}, stdin_data: '')
      # If we're passed a string, convert it to an array beofre passing to capture3
      command = command.split unless command.is_a?(Array)
      Salus::ShellResult.new(*Open3.capture3(env, *command, stdin_data: stdin_data))
    end

    # Add a textual logline to the report. This is for humans
    def log(string)
      @report.log(string)
    end

    # Tag the report as having completed successfully
    def report_success
      @report.pass
    end

    # Tag the report as having failed
    # (ie. a vulnerability was found, the scanner errored out, etc)
    def report_failure
      @report.fail
    end

    # Report information about this scan.
    def report_info(type, message)
      @report.info(type, message)
    end

    # Report a scanner warning such as a possible misconfiguration
    def report_warn(type, message)
      @report.warn(type, message)
    end

    # Report the STDOUT from the scanner.
    def report_stdout(stdout)
      @report.info(:stdout, stdout)
    end

    # Report the STDERR from the scanner.
    def report_stderr(stderr)
      @report.info(:stderr, stderr)
    end

    # Report an error in a scanner.
    def report_error(message, hsh = {})
      hsh[:message] = message
      @report.error(hsh)
    end

    # Report a dependency of the project
    def report_dependency(file, hsh = {})
      hsh = hsh.merge(dependency_file: file)
      @report.dependency(hsh)
    end

    protected

    def validate_bool_option(keyword, value)
      return true if %w[true false].include?(value.to_s.downcase)

      report_warn(:scanner_misconfiguration, "Expecting #{keyword} to be a Boolean (true/false) \
                                              value but got \
                                              #{"'#{value}'" || 'empty string'} \
                                              instead.")
      false
    end

    def validate_string_option(keyword, value, regex)
      return true if value&.match?(regex)

      report_warn(:scanner_misconfiguration, "Expecting #{keyword} to match the regex #{regex} \
                                              but got \
                                              #{"'#{value}'" || 'empty string'} \
                                              instead.")
      false
    end

    def validate_list_option(keyword, value, regex)
      if value.nil?
        report_warn(:scanner_misconfiguration, "Expecting non-empty values in #{keyword}")
        return false
      end

      return true if value&.all? { |option| option.match?(regex) }

      offending_values = value&.reject { |option| option.match?(regex) }
      report_warn(:scanner_misconfiguration, "Expecting values in #{keyword} to match regex \
                                              '#{regex}' value but the offending values are \
                                              '#{offending_values.join(', ')}'.")
      false
    end

    def validate_file_option(keyword, value)
      if value.nil?
        report_warn(:scanner_misconfiguration, "Expecting file/dir defined by #{keyword} to be \
                                                a located in the project repo but got empty string \
                                                instead.")
        return false
      end

      begin
        config_dir = File.realpath(value)
      rescue Errno::ENOENT
        report_warn(:scanner_misconfiguration, "Could not find #{config_dir} defined by \
                                                #{keyword} when expanded into a fully qualified \
                                                path")
        return false
      end

      return true if config_dir.include?(Dir.pwd) # assumes the current directory is the proj dir

      report_warn(:scanner_misconfiguration, "Expecting #{value} defined by \
                                              #{keyword} to be a dir in the project repo but was \
                                               located at '#{config_dir}' instead.")
      false
    end

    def create_flag_option(keyword:, value:, prefix:, between:, suffix:, regex: /.*/, join_by: ',')
      return '' unless validate_bool_option(keyword, value)

      if value.to_s.downcase == "true"
        "#{prefix}#{keyword}#{suffix}"
      else
        ''
      end
    end

    def create_bool_option(keyword:, value:, prefix:, between:, suffix:, regex: /.*/, join_by: ',')
      return '' unless validate_bool_option(keyword, value)

      "#{prefix}#{keyword}#{between}#{Shellwords.escape(value)}#{suffix}"
    end

    def create_file_option(keyword:, value:, prefix:, between:, suffix:, regex: /.*/, join_by: ',')
      return '' unless validate_file_option(keyword, value)

      "#{prefix}#{keyword}#{between}#{Shellwords.escape(value)}#{suffix}"
    end

    def create_string_option(keyword:, value:, prefix:, between:, suffix:, regex: /.*/, join_by: ',')
      return '' unless validate_string_option(keyword, value, regex)

      "#{prefix}#{keyword}#{between}#{Shellwords.escape(value)}#{suffix}"
    end

    def create_list_option(keyword:, value:, prefix:, between:, suffix:, regex: /.*/, join_by: ',')
      return '' unless validate_list_option(keyword, value, regex)

      "#{prefix}#{keyword}#{between}#{Shellwords.escape(value.join(join_by))}#{suffix}"
    end

    def create_list_file_option(keyword:, value:, prefix:, between:, suffix:, regex: /.*/, join_by: ',')
      validated_files = value.select do |file|
        validate_file_option(keyword, file)
      end
      "#{prefix}#{keyword}#{between}#{Shellwords.escape(validated_files.join(join_by))}#{suffix}"
    end

    def multiple_options_if_array(method_name:, keyword:, value:, prefix:, between:, suffix:, max_depth: 1, regex: /.*/, join_by: ',')
      if max_depth > 0 && value.is_a?(Array) # If the maximum recursion depth is reached, just pass the array to the method
        value.reduce('') do |options, item|
          options + multiple_options_if_array(
            method_name: method_name,
            keyword: keyword,
            value: item, # Use each item in the array as the value
            prefix: prefix,
            between: between,
            suffix: suffix,
            max_depth: max_depth - 1,
            regex: regex,
            join_by: join_by
          )
        end
      else
        method(method_name).call(
          keyword: keyword,
          value: value,
          prefix: prefix,
          between: between,
          suffix: suffix,
          regex: regex,
          join_by: join_by
        )
      end
    end

    public

    def build_option(prefix:, suffix:, between:, keyword:, type:, regex: /.*/, join_by: ',')
      keyword_string = keyword.to_s
      if @config.key?(keyword_string)

        value = @config.fetch(keyword_string)

        case type.to_sym.downcase
        when :flag
          multiple_options_if_array(
            method_name: :create_flag_option,
            keyword: keyword,
            value: value,
            prefix: prefix,
            between: between,
            suffix: suffix,
            regex: regex,
            join_by: join_by
          )
        when :string
          multiple_options_if_array(
            method_name: :create_string_option,
            keyword: keyword,
            value: value,
            prefix: prefix,
            between: between,
            suffix: suffix,
            regex: regex,
            join_by: join_by
          )
        when :bool, :booleans
          multiple_options_if_array(
            method_name: :create_bool_option,
            keyword: keyword,
            value: value,
            prefix: prefix,
            between: between,
            suffix: suffix,
            regex: regex,
            join_by: join_by
          )
        when :file
          multiple_options_if_array(
            method_name: :create_file_option,
            keyword: keyword,
            value: value,
            prefix: prefix,
            between: between,
            suffix: suffix,
            regex: regex,
            join_by: join_by
          )
        when :list
          create_list_option(
            keyword: keyword,
            value: value,
            prefix: prefix,
            between: between,
            suffix: suffix,
            regex: regex,
            join_by: join_by
          )
        when :list_file, :file_list
          create_list_file_option(
            keyword: keyword,
            value: value,
            prefix: prefix,
            between: between,
            suffix: suffix,
            regex: regex,
            join_by: join_by
          )
        else
          report_warn(:scanner_misconfiguration, "Could not interpolate config for #{keyword_string} defined by \
          the type of #{type}. ")
          '' # Return an empty string and warn
        end
      else
        '' # Config doesn't have the key in it, so return an empty string
      end
    end

    def build_options(prefix:, suffix:, between:, args:, join_by: ',')
      default_regex = /.*/
      args.reduce('') do |options, (keyword, val)|
        option =
          case val
          when Symbol, String
            build_option(prefix: prefix, suffix: suffix, between: between, type: val, keyword: keyword, join_by: join_by, regex: default_regex)
          when Hash # If you are doing something complicated
            if val[:type].nil?
              report_warn(:scanner_misconfiguration, "Could not interpolate config for #{keyword} \
              defined by since there was no type defined in the hash ")
              '' # Return an empty string and warn
            else
              build_option(
                prefix: val[:prefix] || prefix,
                suffix: val[:suffix] || suffix,
                between: val[:between] || between,
                keyword: keyword,
                type: val[:type],
                regex: val[:regex] || default_regex,
                join_by: val[:join_by] || join_by
              )
            end
          when Regexp # Assume it is a string type if just regex is supplied
            build_option(prefix: prefix, suffix: suffix, between: between, type: :string, keyword: keyword, join_by: join_by, regex: val)
          else
            report_warn(:scanner_misconfiguration, "Could not interpolate config for #{keyword}  \
            defined by since the value provided was not a String, Symbol, Regexp or Hash")
            '' # Return an empty string and warn
          end
        options + option
      end
    end
  end
end
