require 'faraday'
require 'json'
require 'salus/formatting'
require 'salus/bugsnag'

module Salus
  class Report
    include Formatting
    include Salus::SalusBugsnag

    class ExportReportError < StandardError; end

    # FIXME(as3richa): make wrapping behaviour configurable
    WRAP = 100

    CONTENT_TYPE_FOR_FORMAT = {
      'json' => 'application/json',
      'yaml' => 'text/x-yaml',
      'txt'  => 'text/plain',
      'sarif' => 'application/json'
    }.freeze

    SUMMARY_TABLE_HEADINGS = ['Scanner', 'Running Time', 'Required', 'Passed'].freeze

    attr_reader :builds

    def initialize(report_uris: [], builds: {}, project_name: nil, custom_info: nil, config: nil)
      @report_uris = report_uris     # where we will send this report
      @builds = builds               # build hash, could have arbitrary keys
      @project_name = project_name   # the project_name we are scanning
      @scan_reports = []             # ScanReports for each scan run
      @errors = []                   # errors from Salus execution
      @custom_info = custom_info     # some additional info to send
      @config = config               # the configuration for this run
      @running_time = nil            # overall running time for the scan; see #record
    end

    def record
      started_at = monotime
      yield
    ensure
      @running_time = (monotime - started_at).round(2)
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
        running_time: @running_time,
        scans: scans,
        errors: @errors,
        custom_info: @custom_info,
        config: @config
      }.compact
    end

    # Generates the text report.
    def to_s(verbose: false, wrap: WRAP, use_colors: false)
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

      scan_reports.each do |report, _required|
        output += "\n\n#{report.to_s(verbose: verbose, wrap: wrap, use_colors: use_colors)}"
      end

      # Adjust the wrap by 2 because we're wrapping indented paragraphs
      indented_wrap = (wrap.nil? ? nil : wrap - INDENT_SIZE)

      if verbose
        # Dump config in particular as YAML rather than JSON, because salus
        # config files are YAML. Also, stringify the keys before serializing,
        # because the YAML module is sensitive to symbols vs strings. It's
        # annoying
        stringified_config = YAML.dump(@config.deep_stringify_keys, indentation: INDENT_SIZE)
        output += "\n\n==== Salus Configuration\n\n"
      else
        # Include some info on which configuration files were used
        stringified_config = @config[:sources][:valid].join("\n")
        output += "\n\n==== Salus Configuration Files Used:\n\n"
      end

      output += indent(wrapify(stringified_config, indented_wrap))

      if !@errors.empty?
        stringified_errors = JSON.pretty_generate(@errors)
        output += "\n\n==== Salus Errors\n\n"
        output += indent(wrapify(stringified_errors, indented_wrap))
      end

      output += "\n\n#{render_summary(scan_reports, use_colors: use_colors)}"
      output
    end

    def to_yaml
      YAML.dump(to_h)
    end

    def to_json
      JSON.pretty_generate(to_h)
    end

    def to_sarif(config = {})
      Sarif::SarifReport.new(@scan_reports, config).to_sarif
    rescue StandardError => e
      bugsnag_notify(e.class.to_s + " " + e.message + "\nBuild Info:" + @builds.to_s)
    end

    def export_report
      @report_uris.each do |directive|
        # First create the string for the report.
        uri = directive['uri']
        verbose = directive['verbose'] || false
        # Now send this string to its destination.
        report_string = case directive['format']
                        when 'txt' then to_s(verbose: verbose)
                        when 'json' then to_json
                        when 'yaml' then to_yaml
                        when 'sarif' then to_sarif(directive['sarif_options'])
                        else
                          raise ExportReportError, "unknown report format #{directive['format']}"
                        end
        if Salus::Config::REMOTE_URI_SCHEME_REGEX.match?(URI(uri).scheme)
          send_report(uri, report_body(directive), directive['format'])
        else
          # must remove the file:// schema portion of the uri.
          uri_object = URI(uri)
          file_path = "#{uri_object.host}#{uri_object.path}"
          write_report_to_file(file_path, report_string)
        end
      end
    end

    private

    def render_summary(sorted_scan_reports, use_colors:)
      table = sorted_scan_reports.map do |scan_report, required|
        color =
          if scan_report.passed?
            :green
          elsif !required
            :yellow
          else
            :red
          end

        row = [
          scan_report.scanner_name,
          "#{scan_report.running_time}s",
          required ? 'yes' : 'no',
          scan_report.passed? ? 'yes' : 'no'
        ]

        row = row.map { |string| colorize(string, color) } if use_colors
        row
      end

      stringified_table = tabulate(SUMMARY_TABLE_HEADINGS, table)

      status = passed? ? 'PASSED' : 'FAILED'
      status = colorize(status, (passed? ? :green : :red)) if use_colors

      summary = "Overall scan status: #{status}"
      summary += " in #{@running_time}s" unless @running_time.nil?
      summary += "\n\n#{stringified_table}"

      summary
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
        req.headers['X-Scanner'] = "salus"
        req.body = data
      end

      unless response.success?
        raise ExportReportError,
              "POST of Salus report to #{remote_uri} had response status #{response.status}."
      end
    end

    def report_body_hash(config, data)
      return data unless config&.key?('post')

      body_hash = config['post']['additional_params'] || {}
      return body_hash unless config['post']['salus_report_param_name']

      body_hash[config['post']['salus_report_param_name']] = data
      body_hash
    end

    def report_body(config)
      verbose = config['verbose']
      return report_body_hash(config, to_s(verbose: verbose)).to_s if config['format'] == 'txt'

      body = report_body_hash(config, JSON.parse(to_json)) if config['format'] == 'json'
      body = report_body_hash(config, JSON.parse(to_sarif)) if config['format'] == 'sarif'
      return JSON.pretty_generate(body) if %w[json sarif].include?(config['format'])

      return YAML.dump(report_body_hash(config, to_h)) if config['format'] == 'yaml'

      raise ExportReportError, "unknown report format #{directive['format']}"
    end

    def monotime
      # Measure elapsed time with a monotonic clock in order to be resilient
      # to changes in server time
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
