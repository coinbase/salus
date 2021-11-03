require 'json'
require 'set'
require 'sarif/shared_objects'

module Sarif
  class BaseSarif
    include Sarif::SharedObjects

    DEFAULT_URI = "https://github.com/coinbase/salus".freeze

    SARIF_WARNINGS = {
      error: "error",
      warning: "warning",
      note: "note"
    }.freeze

    attr_accessor :config, :required # sarif_options

    def initialize(scan_report, config = {}, repo_path = nil)
      @scan_report = scan_report
      @mapped_rules = {} # map each rule to an index
      @rule_index = 0
      @logs = []
      @uri = DEFAULT_URI
      @issues = Set.new
      @config = config
      @repo_path = repo_path
    end

    def base_path
      @base_path ||= @repo_path.nil? ? nil : File.expand_path(@repo_path)
    end

    # Retrieve tool section for sarif report
    def build_tool(rules: [])
      {
        "driver": {
          "name" => @scan_report.scanner_name,
          "version" => @scan_report.version,
          "informationUri" => @uri,
          "rules" => rules,
          "properties" => {
            "salusEnforced": @required || false
          }
        }
      }
    end

    # Retrieves result section for sarif report
    def build_result(parsed_issue)
      result = {
        "ruleId": parsed_issue[:id],
        "ruleIndex": @mapped_rules[parsed_issue[:id]],
        "level": sarif_level(parsed_issue[:level]),
        "message": {
          "text": parsed_issue[:details]
        },
        "locations": [
          {
            "physicalLocation": {
              "artifactLocation": {
                "uri": parsed_issue[:uri],
                "uriBaseId": "%SRCROOT%"
              }
            }
          }
        ]
      }
      location = result[:locations][0][:physicalLocation]
      if !parsed_issue[:start_line].nil?
        location[:region] = {
          "startLine": parsed_issue[:start_line].to_i,
          "startColumn": parsed_issue[:start_column].to_i
        }
      end

      location[:region][:snippet] = { "text": parsed_issue[:code] } if !parsed_issue[:code].nil?
      result[:properties] = parsed_issue[:properties] unless parsed_issue[:properties].nil?
      result
    end

    def build_rule(parsed_issue)
      # only include one entry per rule id
      if !@mapped_rules.include?(parsed_issue[:id])
        rule = {
          "id": parsed_issue[:id],
          "name": parsed_issue[:name],
          "fullDescription": {
            "text": parsed_issue[:details]
          },
          "messageStrings": parsed_issue[:messageStrings] || {},
          "helpUri": parsed_issue[:help_url] || '',
          "help": {
            "text": "More info: #{parsed_issue[:help_url]}",
            "markdown": "[More info](#{parsed_issue[:help_url]})."
          }
        }
        @mapped_rules[parsed_issue[:id]] = @rule_index
        @rule_index += 1
        rule[:fullDescription][:text] = "errors reported by scanner" if rule[:id] == SCANNER_ERROR
        rule
      end
    end

    # Returns the 'runs' object for a supported/unsupported scanner's report
    def build_runs_object(supported)
      results = []
      rules = []
      @logs.each do |issue|
        parsed_issue = parse_issue(issue)

        next if !parsed_issue

        next if parsed_issue[:suppressed] && @config['include_suppressed'] == false

        next if @required == false && @config['include_suppressed'] == false

        rule = build_rule(parsed_issue)
        rules << rule if rule
        result = build_result(parsed_issue)

        # Add suppresion object for suppressed results
        if parsed_issue[:suppressed] || @required == false
          result['suppressions'] = [{
            'kind': 'external'
          }]
        end
        results << result
      end

      # unique-ify the results
      results = results.each_with_object([]) { |h, result| result << h unless result.include?(h); }

      invocation = build_invocations(@scan_report, supported)
      {
        "tool" => build_tool(rules: rules),
        "conversion" => build_conversion,
        "results" => results,
        "invocations" => [invocation]
      }
    end

    # Returns the conversion object for the SARIF report
    def build_conversion
      {
        "tool": {
          "driver": {
            "name": "Salus",
            "informationUri": DEFAULT_URI
          }
        }
      }
    end

    # Returns a sarif wraning level for a given severity
    def sarif_level(severity)
      case severity
      when "LOW"
        SARIF_WARNINGS[:warning]
      when "MEDIUM"
        SARIF_WARNINGS[:error]
      when "HIGH"
        SARIF_WARNINGS[:error]
      else
        SARIF_WARNINGS[:note]
      end
    end

    def self.report_diff(sarif_new, sarif_old)
      old_scanner_info = {}
      delete_results = Set.new

      sarif_old["runs"].each do |run|
        if run["results"].size.positive?
          scanner = run["tool"]["driver"]["name"]
          run["results"].each { |result| result.delete("ruleIndex") }
          old_scanner_info[scanner] = Set.new run["results"]
        end
      end

      sarif_new["runs"].each do |run| # loop over results for each scanner
        scanner = run["tool"]["driver"]["name"]
        rule_ids = Set.new # rule ids of final results
        scanner_updated = false
        rule_index = 0

        run["results"].each do |result|
          result.delete('ruleIndex')
          if old_scanner_info[scanner]&.include?(result)
            delete_results.add result
            scanner_updated = true
          else
            result["ruleIndex"] = rule_index
            rule_ids.add result['ruleId']
            rule_index += 1
          end
        end

        run["results"].reject! { |result| delete_results.include?(result) }

        if scanner_updated # delete relevant rule ids from rules section
          run["tool"]["driver"]["rules"].select! { |rule| rule_ids.include? rule["id"] }
          if run["tool"]["driver"]["rules"].empty?
            run["invocations"][0]["executionSuccessful"] = true
          end
        end
      end

      sarif_new
    end
  end
end
