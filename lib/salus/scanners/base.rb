require 'open3'
require 'salus/scan_report'
require 'salus/shell_result'
require 'salus/bugsnag'
require 'shellwords'
require 'salus/plugin_manager'
require 'timeout'
module Salus::Scanners
  # Super class for all scanner objects.
  class Base
    class UnhandledExitStatusError < StandardError; end
    class InvalidScannerInvocationError < StandardError; end
    class ConfigFormatError < StandardError; end
    class ScannerTimeoutError < StandardError; end
    # Default unknown version for dependency scanners
    UNKNOWN_VERSION = ''.freeze

    include Salus::SalusBugsnag

    attr_reader :report

    @@mutex = Mutex.new

    def initialize(repository:, config:)
      @repository = repository

      @config = config
      @report = Salus::ScanReport.new(
        name,
        custom_failure_message: @config['failure_message'],
        repository: repository
      )

      version_number = version
      if !version_valid?(version_number) && self.class.instance_methods(false).include?(:version) &&
          self.class != Salus::Scanners::Base
        # scanner version format may get updated
        # report_warn will send warning to bugsnag
        # 2nd condition in the if checks if version is defined on the scanner class
        #     (the false arg) means exclude methods defined on ancestors
        report_warn(:scanner_version_error, "Unable to get #{self.class} version")
        version_number = ''
      end

      @report.add_version(version_number)
    end

    def version
      ''
    end

    def self.supported_languages
      []
    end

    def self.scanner_type
      raise NoMethodError, 'implement in subclass'
    end

    def version_valid?(version)
      return false if !version.is_a?(String)

      !/^\d+\.\d+(.\d+)*$/.match(version).nil?
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
      @@mutex.synchronize do
        @salus_report = salus_report
        salus_report.add_scan_report(@report, required: required)
        @builds = @salus_report&.builds
      end

      begin
        @report.record do
          Timeout.timeout(scanner_timeout) { run }
        end

        update_report_status(pass_on_raise) if @report.errors.any?
      rescue Timeout::Error
        error_message = "Scanner #{name} timed out after #{scanner_timeout} seconds"
        timeout_error_data = {
          message: error_message,
          error_class: ScannerTimeoutError
        }

        update_report_status(pass_on_raise)
        record_error(timeout_error_data)
        bugsnag_notify(error_message)

        # Propagate this error if desired
        raise ScannerTimeoutError, timeout_error_data[:message] if reraise
      rescue StandardError => e
        error_data = {
          message: "Unhandled exception running #{name}: #{e.class}: #{e}",
          error_class: e.class,
          backtrace: e.backtrace.take(5)
        }

        update_report_status(pass_on_raise)

        # Record the error so that the Salus report captures the issue.
        record_error(error_data)

        raise if reraise
      ensure
        @@mutex.synchronize do
          Salus::PluginManager.send_event(:scan_executed, { salus_report: @salus_report,
                                                            scan_report: @report })
        end
      end
    end

    # Runs a command on the terminal.
    def run_shell(command, env: {}, stdin_data: '',
                  chdir: File.expand_path(@repository&.path_to_repo))
      # If we're passed a string, convert it to an array before passing to capture3
      command = command.split unless command.is_a?(Array)
      Salus::PluginManager.send_event(:run_shell, command, chdir: chdir)
      #  chdir: '/some/directory'
      opts = { stdin_data: stdin_data }
      opts[:chdir] = chdir unless chdir.nil? || chdir == "."
      Salus::ShellResult.new(*Open3.capture3(env, *command, opts))
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
      Salus::PluginManager.send_event(:report_warn, { type: type, message: message })
      if @builds
        scanner = @report.scanner_name
        message = "#{scanner} warning: #{type}, #{message}, build: #{@builds}"
      end
      bugsnag_notify(message)
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
      Salus.hard_error_encountered = true if hsh.dig(:hard_error) == true
      hsh[:message] = message
      @report.error(hsh)
      message = "#{@report.scanner_name} error: #{message}, build: #{@builds}" if @builds
      bugsnag_notify(message)
    end

    # Report a dependency of the project
    def report_dependency(file, hsh = {})
      hsh = hsh.merge(dependency_file: file)
      @report.dependency(hsh)
    end

    protected

    def update_report_status(pass_on_raise)
      return @report.fail if @report.errors.any? { |err| err.dig(:hard_error) == true }

      pass_on_raise ? @report.pass : @report.fail
    end

    def record_error(error)
      @report.error(error)
      @@mutex.synchronize { @salus_report.error(error) }
    end

    def validate_bool_option(keyword, value)
      return true if %w[true false].include?(value.to_s.downcase)

      report_warn(:scanner_misconfiguration, "Expecting #{keyword} to be a Boolean (true/false) "\
                                              "value but got "\
                                              "#{"'#{value}'" || 'empty string'} "\
                                              "instead.")
      false
    end

    def validate_string_option(keyword, value, regex)
      return true if value&.match?(regex)

      report_warn(:scanner_misconfiguration, "Expecting #{keyword} to match the regex #{regex} "\
                                              "but got "\
                                              "#{"'#{value}'" || 'empty string'} "\
                                              "instead.")
      false
    end

    def validate_list_option(keyword, value, regex)
      if value.nil?
        report_warn(:scanner_misconfiguration, "Expecting non-empty values in #{keyword}")
        return false
      end

      return true if value&.all? { |option| option.match?(regex) }

      offending_values = value&.reject { |option| option.match?(regex) }
      report_warn(:scanner_misconfiguration, "Expecting values in #{keyword} to match regex "\
                                              "'#{regex}' value but the offending values are "\
                                              "'#{offending_values.join(', ')}'.")
      false
    end

    def validate_file_option(keyword, value, chdir: File.expand_path(@repository&.path_to_repo))
      if value.nil?
        report_warn(:scanner_misconfiguration, "Expecting file/dir defined by #{keyword} to be a"\
                                                "location in the project repo but got empty "\
                                                "string instead.")
        return false
      end

      begin
        config_dir = File.realpath(value, chdir)
      rescue Errno::ENOENT
        report_warn(:scanner_misconfiguration, "Could not find #{config_dir} defined by "\
                                                "#{keyword} when expanded into a fully qualified "\
                                                "path. Value was #{value}")
        return false
      end

      # Dir.pwd reference needs to be removed
      # Dir.pwd) # assumes the current directory is the proj dir
      return true if config_dir.include?(chdir) # assumes the current directory is the proj dir

      report_warn(:scanner_misconfiguration, "Expecting #{value} defined by "\
                                              "#{keyword} to be a dir in the project repo but was "\
                                               "located at '#{config_dir}' instead.")
      false
    end

    # Ex. in scanner config yaml, 'level' can be 'LOW', 'MEDIUM', or 'HIGH'.
    #     We want
    #     level: LOW     mapped to config option -l
    #     level: MEDIUM  mapped to config option -ll
    #     level: HIGH    mapped to config option -lll
    #
    # Example input
    #     {{'level' => { 'LOW' => 'l', 'MEDIUM' => 'll', 'HIGH' => 'lll'},
    #      {'confidence' => { 'LOW' => 'i', 'MEDIUM' => 'ii', 'HIGH' => 'iii'}}
    def build_flag_args_from_string(string_flag_map)
      arg_map = {}
      string_flag_map.each do |string_key, flag_map|
        arg_map.merge!(build_flag_arg_from_string(string_key, flag_map))
      end
      arg_map
    end

    def build_flag_arg_from_string(key, flag_map)
      arg_map = {}
      val = @config[key]
      if val
        val.upcase!
        flag = flag_map[val]
        if flag
          @config[flag] = true
          arg_map[flag.to_sym] = { type: :flag, keyword: flag }
        else
          msg = "User specified val #{val} for key #{key} not found in scanner configs"
          report_warn(:scanner_misconfiguration, msg)
        end
      end
      arg_map
    end

    def create_flag_option(keyword:, value:, prefix:, suffix:)
      return '' unless validate_bool_option(keyword, value)

      if value.to_s.downcase == "true"
        "#{prefix}#{keyword}#{suffix}"
      else
        ''
      end
    end

    def create_bool_option(keyword:, value:, prefix:, separator:, suffix:)
      return '' unless validate_bool_option(keyword, value)

      "#{prefix}#{keyword}#{separator}#{Shellwords.escape(value)}#{suffix}"
    end

    def create_file_option(keyword:, value:, prefix:, separator:, suffix:)
      return '' unless validate_file_option(keyword, value)

      "#{prefix}#{keyword}#{separator}#{Shellwords.escape(value)}#{suffix}"
    end

    def create_string_option(keyword:, value:, prefix:, separator:, suffix:, regex: /.*/)
      return '' unless validate_string_option(keyword, value, regex)

      "#{prefix}#{keyword}#{separator}#{Shellwords.escape(value)}#{suffix}"
    end

    def create_list_option(
      keyword:,
      value:,
      prefix:,
      separator:,
      suffix:,
      regex: /.*/,
      join_by: ','
    )
      return '' unless validate_list_option(keyword, value, regex)

      "#{prefix}#{keyword}#{separator}#{Shellwords.escape(value.join(join_by))}#{suffix}"
    end

    def create_list_file_option(keyword:, value:, prefix:, separator:, suffix:, join_by: ',')
      validated_files = value.select do |file|
        validate_file_option(keyword, file)
      end
      "#{prefix}#{keyword}#{separator}#{Shellwords.escape(validated_files.join(join_by))}#{suffix}"
    end

    def fetch_exception_ids
      exceptions = @config.fetch('exceptions', [])
      ids = []
      exceptions.each do |exception|
        except = Salus::ConfigException.new(exception)
        unless except.valid?
          report_error(
            'malformed exception; expected a hash with keys advisory_id, changed_by, notes',
            exception: exception,
            hard_error: true
          )
          next
        end
        ids << except.id.to_s if except.active?
      end
      ids
    end

    public

    def build_option(
      prefix:,
      suffix:,
      separator:,
      keyword:,
      value:,
      type:,
      regex: /.*/,
      join_by: ',',
      max_depth: 1
    )

      clean_type = type.to_sym.downcase
      case clean_type
      when :flag, :string, :bool, :booleans, :file # Allow repeat values
        if max_depth.positive? && value.is_a?(Array)
          value.reduce('') do |options, item|
            options + build_option(
              type: clean_type,
              keyword: keyword,
              value: item, # Use each item in the array as the value
              prefix: prefix,
              separator: separator,
              suffix: suffix,
              max_depth: max_depth - 1,
              regex: regex,
              join_by: join_by
            )
          end
        else
          case clean_type
          when :string
            create_string_option(
              keyword: keyword,
              value: value,
              prefix: prefix,
              suffix: suffix,
              separator: separator,
              regex: regex
            )
          when :bool, :booleans
            create_bool_option(
              keyword: keyword,
              value: value,
              prefix: prefix,
              suffix: suffix,
              separator: separator
            )
          when :flag
            create_flag_option(keyword: keyword, value: value, prefix: prefix, suffix: suffix)
          when :file
            create_file_option(
              keyword: keyword,
              value: value,
              prefix: prefix,
              suffix: suffix,
              separator: separator
            )
          end
        end
      when :list
        create_list_option(
          keyword: keyword,
          value: value,
          prefix: prefix,
          separator: separator,
          suffix: suffix,
          regex: regex,
          join_by: join_by
        )
      when :list_file, :file_list
        create_list_file_option(
          keyword: keyword,
          value: value,
          prefix: prefix,
          separator: separator,
          suffix: suffix,
          join_by: join_by
        )
      else
        report_warn(
          :scanner_misconfiguration,
          "Could not interpolate config #{keyword} "\
          "to the type of #{type}. "
        )
        '' # Return an empty string and warn
      end
    end

    def get_config_value(key, overrides)
      return overrides[key] if overrides&.key?(key)

      @config.fetch(key)
    end

    def has_key?(key, overrides)
      @config.key?(key) || overrides&.key?(key)
    end

    # config_overrides allows easy overrides of the @config values
    def build_options(prefix:, suffix:, separator:, args:, join_by: ',', config_overrides: {})
      default_regex = /.*/
      args.reduce('') do |options, (keyword, type_value)|
        keyword_string = keyword.to_s
        # @config is a hash
        option = if has_key?(keyword_string, config_overrides)
                   config_value = get_config_value(keyword_string, config_overrides)
                   case type_value
                   when Symbol, String
                     build_option(
                       prefix: prefix,
                       suffix: suffix,
                       separator: separator,
                       type: type_value,
                       keyword: keyword_string,
                       value: config_value,
                       join_by: join_by,
                       regex: default_regex
                     )
                   when Hash # If you are doing something complicated
                     if type_value[:type].nil?
                       warning = "Could not interpolate config "\
                         "defined by since there was no type defined in the hash "
                       report_warn(:scanner_misconfiguration, warning)
                       '' # Return an empty string and warn
                     else
                       build_option(
                         prefix: type_value[:prefix] || prefix,
                         suffix: type_value[:suffix] || suffix,
                         separator: type_value[:separator] || separator,
                         keyword: type_value[:keyword] || keyword_string,
                         value: config_value,
                         type: type_value[:type],
                         regex: type_value[:regex] || default_regex,
                         join_by: type_value[:join_by] || join_by
                       )
                     end
                   when Regexp # Assume it is a string type if just regex is supplied
                     result = build_option(
                       prefix: prefix,
                       suffix: suffix,
                       separator: separator,
                       type: :string,
                       keyword: keyword_string,
                       value: config_value,
                       join_by: join_by,
                       regex: type_value
                     )
                     # In new versions of gosec, nosec-tag matches the exact string
                     # For example, In previous versions;
                     #  - running the command `gosec -nosec-tag=falsepositive .`
                     #    would match all occurrences of /* #falsepositive */ in go files
                     # In current versions:
                     #  - running the command `gosec -nosec-tag=falsepositive .`
                     #    would match only match /* falsepositive */ in go files
                     #  - you would have to modify your string to match #falsepositive
                     #    running the command `gosec -nosec-tag=#falsepositive .`
                     #    would match all occurrences of /* #falsepositive */ in go files
                     # To prevent salus functionality from changing, this line adds a pound
                     # sign to alternative nosec string
                     result = "-nosec-tag=##{config_value} " if result.include? "-nosec-tag="
                     result
                   else
                     warning = "Could not interpolate config for #{keyword} "\
                       "defined by since the value provided was not a String, "\
                       "Symbol, Regexp or Hash"
                     report_warn(:scanner_misconfiguration, warning)
                     '' # Return an empty string and warn
                   end
                 else
                   '' # Not in the config, just return an empty string
                 end
        options + option
      end
    end

    def scanner_timeout
      scanner_timeout_config_param = @config['scanner_timeout_s']
      # If a developer mistakenly defines this parameter
      # as a non-integer value, let it be known
      is_timeout_valid =
        (scanner_timeout_config_param.is_a?(Integer) ||
        scanner_timeout_config_param.is_a?(Float)) &&
        scanner_timeout_config_param >= 0
      unless is_timeout_valid
        error_message = "'scanner_timeout_s' parameter must be an integer or float " \
          "and should not be negative"
        bugsnag_notify(error_message)
        raise ConfigFormatError, error_message
      end

      scanner_timeout_config_param
    end
  end
end
