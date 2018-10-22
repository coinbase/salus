require 'faraday'
require 'json'

module Salus
  class Report
    class ExportReportError < StandardError; end

    NUM_CHAR_IN_BAR = 20
    BAR = ('=' * NUM_CHAR_IN_BAR).freeze
    SPECIAL_BAR = ('#' * NUM_CHAR_IN_BAR).freeze

    SCAN_RESULT_WORD = {
      true => 'passed',
      false => 'failed'
    }.freeze

    CONTENT_TYPE_FOR_FORMAT = {
      'json' => 'application/json',
      'yaml' => 'text/x-yaml',
      'txt'  => 'text/plain'
    }.freeze

    def initialize(report_uris: [], project_name: '', custom_info: '')
      @report_uris = report_uris   # where we will send this report
      @project_name = project_name # the project_name we are scanning
      @scans = {}                  # scan logs
      @info = {}                   # info about Salus execution
      @errors = {}                 # errors from Salus execution
      @custom_info = custom_info   # some additional info to send
      @configuration = {}          # the configuration for this run
    end

    def scan_passed(scanner, result)
      scan_log(scanner, 'passed', result)
    end

    def scan_stdout(scanner, stdout)
      scan_log(scanner, 'stdout', stdout)
    end

    def scan_stderr(scanner, stderr)
      scan_log(scanner, 'stderr', stderr)
    end

    def scan_info(scanner, type, message)
      @scans[scanner] ||= {}
      @scans[scanner]['info'] ||= {}
      @scans[scanner]['info'][type] ||= []
      @scans[scanner]['info'][type] << message
    end

    def scan_log(scanner, log_type, log)
      @scans[scanner] ||= {}
      @scans[scanner][log_type] = log
    end

    def salus_runtime_error(error_data)
      salus_error('Salus', error_data)
    end

    # Record a list of any errors that Salus encounters.
    # These might be Salus code or from scanners.
    def salus_error(error_origin, error_data)
      # If we have a bugsnag api key and we're not running tests
      if ENV['BUGSNAG_API_KEY'] && !ENV['RUNNING_SALUS_TESTS']
        Bugsnag.notify([error_origin, error_data])
      end

      @errors[error_origin] ||= []
      @errors[error_origin] << error_data
    end

    def has_failure?(source)
      @scans.key?(source) && @scans[source].key?("passed") && @scans[source]["passed"] == false
    end

    def configuration_source(source)
      @configuration['sources'] ||= []
      @configuration['sources'] << source
    end

    def configuration_directive(directive, value)
      @configuration[directive] = value
    end

    def to_h
      {
        project_name: @project_name,
        scans: @scans,
        info: @info,
        errors: @errors,
        version: VERSION,
        custom_info: @custom_info,
        configuration: @configuration
      }
    end

    def to_json
      JSON.pretty_generate(to_h)
    end

    # Generates the text report.
    def to_s(verbose: false)
      lines = []
      lines << "#{SPECIAL_BAR} Salus Scan v#{VERSION} for #{@project_name} #{SPECIAL_BAR}"

      if @scans.any?
        @scans.each do |scanner, scan_data|
          # Scanner title which gives the high level picture
          scanner_title = "\t#{scanner}"
          scan_result = SCAN_RESULT_WORD[scan_data['passed']]
          scanner_title += " => #{scan_result}" unless scan_result.nil?
          lines << scanner_title

          # Additional data about the scan. Give stdout, stderr and if verbose, also give info.
          lines << "STDOUT:\n#{scan_data['stdout']}" unless scan_data['stdout'].nil?
          lines << "STDERR:\n#{scan_data['stderr']}" unless scan_data['stderr'].nil?

          if verbose
            scan_data['info']&.each do |type, messages|
              lines << "INFO - #{type}"
              lines += messages.map { |message| "\t#{message}" }
            end
          end
        end
      end

      if verbose && @info.any?
        lines << "#{BAR} Scan Info #{BAR}"
        @info.each do |type, messages|
          lines << type
          lines += messages.each { |message| "\t#{message}" }
        end
      end

      # Only add configuration if verbose mode is on.
      if verbose
        lines << "\n"
        lines << "#{BAR} Salus Configuration #{BAR}"
        lines += @configuration.map { |type, value| "#{type}: #{value}" }
      end

      if @errors.any?
        lines << "\n"
        lines << "#{BAR} Salus Errors #{BAR}"
        lines += @errors.map { |klass, data| "\t#{klass} - #{data}" }
      end

      lines.map! { |line| wrap(line) }
      lines.join("\n")
    end

    def to_yaml
      YAML.dump(to_h)
    end

    # Send the report to given URIs (which could be remove or local).
    def export_report
      @report_uris.each do |directive|
        # First create the string for the report.
        uri = directive['uri']
        verbose = directive['verbose'] || false
        report_string = case directive['format']
                        when 'txt' then to_s(verbose: verbose)
                        when 'json' then to_json
                        when 'yaml' then to_yaml
                        else
                          raise ExportReportError, "unknown report format #{directive['format']}"
                        end

        # Now send this string to its destination.
        if Salus::Config::REMOTE_URI_SCHEME_REGEX.match?(URI(uri).scheme)
          send_report(uri, report_string, directive['format'])
        else
          # must remove the file:// schema portion of the uri.
          uri_object = URI(uri)
          file_path = "#{uri_object.host}#{uri_object.path}"
          write_report_to_file(file_path, report_string)
        end
      end
    end

    private

    # Wrap lines to 100 chars by default
    def wrap(text, line_width = 100)
      text.gsub(/(.{1,#{line_width}})/, "\\1\n")
    end

    def write_report_to_file(report_file_path, report_string)
      File.open(report_file_path, 'w') { |file| file.write(report_string) }
    rescue SystemCallError => e
      raise ExportReportError,
            "Cannot write file #{report_file_path} - #{e.class}: #{e.message}"
    end

    def send_report(remote_uri, data, format)
      response = Faraday.post do |req|
        req.url remote_uri
        req.headers['Content-Type'] = CONTENT_TYPE_FOR_FORMAT[format]
        req.body = data
      end

      unless response.success?
        raise ExportReportError,
              "POST of Salus report to #{remote_uri} had response status #{response.status}."
      end
    end
  end
end
