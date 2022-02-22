require 'json'
require 'deepsort'
require 'salus/formatting'
require 'salus/bugsnag'

# Adding aliases to prevent deep_sort from failing when comparing symbols and strings
class Symbol
  alias old_salus_compare <=>
  def <=>(other)
    if other.is_a? String
      inspect <=> other
    else
      old_salus_compare other
    end
  end
end
class String
  alias old_salus_compare <=>
  def <=>(other)
    if other.is_a? Symbol
      old_salus_compare other.inspect
    else
      old_salus_compare other
    end
  end
end
module Salus
  class Report
    include Formatting
    include Salus::SalusBugsnag

    class ExportReportError < StandardError; end

    # FIXME(as3richa): make wrapping behaviour configurable
    WRAP = 100

    SUMMARY_TABLE_HEADINGS = ['Scanner', 'Running Time', 'Required', 'Passed'].freeze

    attr_reader :builds
    attr_accessor :full_diff_sarif, :report_uris

    def initialize(report_uris: [], builds: {}, project_name: nil, custom_info: nil, config: nil,
                   repo_path: nil, filter_sarif: nil, ignore_config_id: nil,
                   report_filter: DEFAULT_REPORT_FILTER, merge_by_scanner: false)
      @report_uris = report_uris           # where we will send this report
      @builds = builds                     # build hash, could have arbitrary keys
      @project_name = project_name         # the project_name we are scanning
      @scan_reports = []                   # ScanReports for each scan run
      @errors = []                         # errors from Salus execution
      @custom_info = custom_info           # some additional info to send
      @config = config                     # the configuration for this run
      @running_time = nil                  # overall running time for the scan; see #record
      @filter_sarif = filter_sarif         # Filter out results from this file
      @repo_path = repo_path               # path to repo
      @ignore_config_id = ignore_config_id # ignore id in salus config
      @report_filter = report_filter       # filter reports that'll run based on their configuration
      @full_diff_sarif = nil
      @merge_by_scanner = merge_by_scanner # Flag to group to_h and to_s results by scanner
    end

    # Syntatical sugar to apply report hash filters
    def apply_report_hash_filters(report_hash)
      Salus::PluginManager.apply_filter(:salus_report, :filter_report_hash, report_hash)
    end

    def apply_report_sarif_filters(sarif_json)
      Salus::PluginManager.apply_filter(:salus_report, :filter_report_sarif, sarif_json)
    end

    # Syntatical sugar register salus_report filters
    def self.register_filter(filter)
      Salus::PluginManager.register_filter(:salus_report, filter)
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

    # We may have several scan reports from a given scanner.
    # This will typically be from recusive scannings.  When
    # @merge_by_scanner is true we will merge the ScanReports
    # from a given scanner together.
    #
    # @returns [Array<ScanReport>]
    def merged_reports
      return @scan_reports unless @merge_by_scanner

      reports = {}
      @scan_reports.each do |report, required|
        if reports.key?(report.scanner_name)
          report = reports[report.scanner_name].first.merge!(report)
        end
        reports[report.scanner_name] = [report, required]
      end

      reports.values
    end

    def to_h
      # We flatten the scan_reports by scanner here
      scans = merged_reports.map { |report, _required| [report.scanner_name, report.to_h] }.to_h

      report_hash = {
        version: VERSION,
        project_name: @project_name,
        passed: passed?,
        running_time: @running_time,
        scans: scans,
        errors: @errors,
        custom_info: @custom_info,
        config: @config
      }.compact

      apply_report_hash_filters(report_hash)
    end

    # Generates the text report.
    def to_s(verbose: false, wrap: WRAP, use_colors: false)
      output = "==== Salus Scan v#{VERSION}"
      output += " for #{@project_name}" unless @project_name.nil?

      # Sort scan reports required before optional, failed before passed,
      # and alphabetically by scanner name
      scan_reports = merged_reports.sort_by do |report, required|
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
        stringified_config = @config&.dig(:sources, :valid)&.join("\n").to_s
        output += "\n\n==== Salus Configuration Files Used:\n\n"
      end

      output += indent(wrapify(stringified_config, indented_wrap))

      if @ignore_config_id != "" && !@ignore_config_id.nil?
        output += "\n  IDs ignored in salus config:\n\t#{@ignore_config_id}"
      end

      if !@errors.empty?
        stringified_errors = JSON.pretty_generate(@errors)
        output += "\n\n==== Salus Errors\n\n"
        output += indent(wrapify(stringified_errors, indented_wrap))
      end

      output += "\n\n#{render_summary(scan_reports, use_colors: use_colors)}"
      output
    end

    def to_yaml
      YAML.dump(to_h.deep_sort)
    rescue StandardError => e
      bugsnag_notify(e.inspect + "\n" + e.message + "\nResult String: " + to_h.to_s)
      YAML.dump(to_h)
    end

    def to_json
      JSON.pretty_generate(to_h.deep_sort)
    rescue StandardError => e
      bugsnag_notify(e.inspect + "\n" + e.message + "\nResult String: " + to_h.to_s)
      JSON.pretty_generate(to_h)
    end

    def to_sarif(config = {})
      sarif_json = Sarif::SarifReport.new(@scan_reports, config, @repo_path).to_sarif
      begin
        sorted_sarif = JSON.parse(sarif_json).deep_sort
      rescue StandardError => e
        bugsnag_notify(e.inspect + "\n" + e.message + "\nResult String: " + to_h.to_s)
        sorted_sarif = JSON.parse(sarif_json)
      end
      # We will validate to ensure the applied filter
      # doesn't produce any invalid SARIF
      sarif_json = JSON.pretty_generate(sorted_sarif)
      Sarif::SarifReport.validate_sarif(apply_report_sarif_filters(sarif_json))
    rescue StandardError => e
      bugsnag_notify(e.class.to_s + " " + e.message + "\nBuild Info:" + @builds.to_s)
    end

    def to_sarif_diff
      diff_report = {}
      curr_sarif_data = JSON.parse(to_sarif)
      filter_sarif_file = File.join(@repo_path, @filter_sarif)
      filter_sarif_data = JSON.parse(File.read(filter_sarif_file))
      curr_sarif_results = get_sarif_results(curr_sarif_data)
      filter_sarif_results = get_sarif_results(filter_sarif_data)
      diff = (curr_sarif_results - filter_sarif_results).to_a

      diff_report['report_type'] = 'salus_sarif_diff'
      diff_report['filtered_results'] = diff
      diff_report['builds'] = to_h[:config][:builds]
      JSON.pretty_generate(diff_report)
    end

    def get_sarif_results(sarif_data)
      sarif_results = Set.new
      sarif_data["runs"].each do |run|
        scanner_name = run['tool']['driver']['name']
        run["results"].each do |result|
          # delete ruleIndex because the vulnerabilities of two scans may be
          # same but ordered differently
          result.delete('ruleIndex')
          result['scanner_name'] = scanner_name
          sarif_results.add(result)
        end
      end
      sarif_results
    end

    def to_full_sarif_diff
      JSON.pretty_generate(@full_diff_sarif)
    end

    def to_cyclonedx(config = {})
      cyclonedx_bom = Cyclonedx::Report.new(@scan_reports, config).to_cyclonedx
      begin
        sorted_cyclonedx_bom = cyclonedx_bom.deep_sort
      rescue StandardError => e
        bugsnag_notify(e.inspect + "\n" + e.message + "\nResult String: " + to_h.to_s)
        sorted_cyclonedx_bom = cyclonedx_bom
      end

      cyclonedx_report = {
        autoCreate: true,
        projectName: config['cyclonedx_project_name'] || "",
        projectVersion: "1",
        bom: Base64.strict_encode64(JSON.generate(sorted_cyclonedx_bom))
      }
      begin
        sorted_cyclonedx_report = cyclonedx_report.deep_sort
      rescue StandardError => e
        bugsnag_notify(e.inspect + "\n" + e.message + "\nResult String: " + to_h.to_s)
        sorted_cyclonedx_report = cyclonedx_report
      end
      JSON.pretty_generate(sorted_cyclonedx_report)
    rescue StandardError => e
      bugsnag_notify(e.class.to_s + " " + e.message + "\nBuild Info:" + @builds.to_s)
    end

    def publish_report(directive)
      # First create the string for the report.
      uri = directive['uri']
      verbose = directive['verbose'] || false
      # Now send this string to its destination.
      report_string = case directive['format']
                      when 'txt' then to_s(verbose: verbose)
                      when 'json' then to_json
                      when 'yaml' then to_yaml
                      when 'sarif' then to_sarif(directive['sarif_options'] || {})
                      when 'sarif_diff' then to_sarif_diff
                      when 'sarif_diff_full' then to_full_sarif_diff
                      when 'cyclonedx-json' then to_cyclonedx(directive['cyclonedx_options'] || {})
                      else
                        raise ExportReportError, "unknown report format #{directive['format']}"
                      end
      if Salus::Config::REMOTE_URI_SCHEME_REGEX.match?(URI(uri).scheme)
        Salus::ReportRequest.send_report(directive, report_body(directive), uri)
      else
        # must remove the file:// schema portion of the uri.
        uri_object = URI(uri)
        file_path = "#{uri_object.host}#{uri_object.path}"
        if !safe_local_report_path?(file_path)
          bad_path_msg = "Local report uri #{file_path} should be relative to repo path and " \
                         "cannot have invalid chars"
          raise StandardError, bad_path_msg
        end
        write_report_to_file(file_path, report_string)
      end
    end

    def satisfies_filter?(directive, filter_key, filter_value)
      directive.key?(filter_key) && (
        # rubocop:disable Style/MultipleComparison
        directive[filter_key] == filter_value || filter_value == '*'
        # rubocop:enable Style/MultipleComparison
      )
    end

    def export_report
      return [] if @report_filter == 'none'

      recovered_values = @report_filter.split(':', 2)
      filter_key = recovered_values[0]
      filter_value = recovered_values[1]
      if @report_filter != 'all' && (filter_key.to_s == '' || filter_value.to_s == '')
        raise ExportReportError, 'Poorly formatted report filter found. ' \
          'Filter key and pattern must be non-empty strings'
      end

      @report_uris.each do |directive|
        if @report_filter == 'all' || satisfies_filter?(directive, filter_key, filter_value)
          publish_report(directive)
        end
      end
    rescue StandardError => e
      raise e if ENV['RUNNING_SALUS_TESTS']

      puts "Could not send Salus report: (#{e.class}: #{e.message}), #{e.backtrace}"
      e = "Could not send Salus report. Exception: #{e}, Build info: #{builds}, #{e.backtrace}"
      bugsnag_notify(e)
    end

    def safe_local_report_path?(path)
      Salus::PathValidator.new(@repo_path).local_to_base?(path)
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
          "#{scan_report.running_time || 0}s",
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

    def report_body_hash(config, data)
      return data unless config&.key?('post') && config['post'].present?

      body_hash = config['post']['additional_params'] || {}
      return body_hash unless config['post']['salus_report_param_name']

      body_hash[config['post']['salus_report_param_name']] = data
      body_hash
    end

    def report_body(config)
      verbose = config['verbose']
      return report_body_hash(config, to_s(verbose: verbose)).to_s if config['format'] == 'txt'

      body = case config['format']
             when 'json'
               to_json
             when 'sarif'
               to_sarif(config['sarif_options'] || {})
             when 'sarif_diff'
               to_sarif_diff
             when 'sarif_diff_full'
               to_full_sarif_diff
             when 'cyclonedx-json'
               to_cyclonedx(config['cyclonedx_options'] || {})
             end

      if %w[json sarif sarif_diff sarif_diff_full cyclonedx-json].include?(config['format'])
        body = JSON.parse(body)
        return JSON.pretty_generate(report_body_hash(config, body))
      end

      # When creating a report body for yaml #to_yaml is not called
      # This sorts the hash before the report is generated
      begin
        body = to_h.deep_sort
      rescue StandardError => e
        bugsnag_notify(e.inspect + "\n" + e.message + "\nResult String: " + to_h.to_s)
        body = to_h
      end
      return YAML.dump(report_body_hash(config, body)) if config['format'] == 'yaml'

      raise ExportReportError, "unknown report format #{directive['format']}"
    end

    def monotime
      # Measure elapsed time with a monotonic clock in order to be resilient
      # to changes in server time
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
