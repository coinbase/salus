require 'faraday'
require 'json'

module Salus
  class Report
    class ExportReportError < StandardError; end

    # FIXME(as3richa): make wrapping behaviour configurable
    WRAP = 100

    CONTENT_TYPE_FOR_FORMAT = {
      'json' => 'application/json',
      'yaml' => 'text/x-yaml',
      'txt'  => 'text/plain'
    }.freeze

    def initialize(report_uris: [], project_name: nil, custom_info: nil, config: nil)
      @report_uris = report_uris     # where we will send this report
      @project_name = project_name   # the project_name we are scanning
      @scan_reports = []             # ScanReports for each scan run
      @errors = []                   # errors from Salus execution
      @custom_info = custom_info     # some additional info to send
      @config = config               # the configuration for this run
    end

    def passed?
      @scan_reports.all? { |scan_report, required| !required || scan_report.passed? }
    end

    def add_scan_report(scan_report, required:)
      @scan_reports << [scan_report, required]
    end

    def error(hsh)
      @errors << hsh
    end

    def to_h
      scans = @scan_reports.map { |report, _required| [report.scanner_name, report.to_h] }.to_h

      {
        version: VERSION,
        project_name: @project_name,
        passed: passed?,
        scans: scans,
        errors: @errors,
        custom_info: @custom_info,
        config: @config
      }.compact
    end

    # Generates the text report.
    def to_s(verbose: false, wrap: WRAP)
      output = "==== Salus Scan v#{VERSION}"
      output += " for #{@project_name}" unless @project_name.nil?

      # Sort scan reports required before optional, failed before passed,
      # and alphabetically by scanner name
      scan_reports = @scan_reports.sort_by do |report, required|
        [
          required ? 0 : 1,
          report.passed? ? 1 : 0,
          report.scanner_name
        ]
      end

      # Print a summary of the scan results
      # FIXME(as3richa): this should be a pretty table :)
      output += "\n\nRan #{scan_reports.length} scanner(s):"
      scan_reports.each do |report, required|
        output += "\n- #{report.scanner_name}: #{report.passed? ? 'PASSED' : 'FAILED'}"
        output += " in #{report.running_time}s" unless report.running_time.nil?
        output += required ? ' (required)' : ' (not required)'
      end

      scan_reports.each do |report, _required|
        output += "\n\n#{report.to_s(verbose: verbose, wrap: wrap)}"
      end

      # Adjust the wrap by 2 because we're wrapping indented paragraphs
      wrap = (wrap.nil? ? nil : wrap - 2)

      # Only add config if verbose mode is on.
      if verbose
        # Dump config in particular as YAML rather than JSON, because salus
        # config files are YAML. Also, stringify the keys before serializing,
        # because the YAML module is sensitive to symbols vs strings. It's
        # annoying
        stringified_config = YAML.dump(deep_stringify_keys(@config), indentation: 2)
        output += "\n\n==== Salus Configuration\n\n"
        output += indent(wrapify(stringified_config, wrap))
      end

      if !@errors.empty?
        stringified_errors = JSON.pretty_generate(@errors)
        output += "\n\n==== Salus Errors\n\n"
        output += indent(wrapify(stringified_errors, wrap))
      end

      output
    end

    def to_yaml
      YAML.dump(to_h)
    end

    def to_json
      JSON.pretty_generate(to_h)
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

    def deep_stringify_keys(datum)
      case datum
      when Hash then datum.map { |key, value| [key.to_s, deep_stringify_keys(value)] }.to_h
      when Array then datum.map { |value| deep_stringify_keys(value) }
      else datum
      end
    end

    # FIXME(as3richa): factor this out along with the identical version
    # in scan_report.rb. Maybe have a Formatting mixin module for wrapping,
    # indentation, coloring, tabulation...
    def wrapify(string, wrap)
      return string if wrap.nil?

      parts = []

      string.each_line("\n").each do |line|
        if line == "\n"
          parts << "\n"
          next
        end

        line = line.chomp
        index = 0

        while index < line.length
          parts << line.slice(index, wrap) + "\n"
          index += wrap
        end
      end

      parts.join
    end

    def indent(text)
      # each_line("\n") rather than split("\n") because the latter
      # discards trailing empty lines. Also, don't indent empty lines
      text.each_line("\n").map { |line| line == "\n" ? "\n" : ("  " + line) }.join
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
