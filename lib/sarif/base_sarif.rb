module Sarif
  class BaseSarif
    DEFAULT_URI = "https://github.com/coinbase/salus".freeze

    SARIF_WARNINGS = {
      error: "error",
      warning: "warning",
      note: "note"
    }.freeze

    def initialize(scan_report)
      @scan_report = scan_report
      @mapped_rules = {} # map each rule to an index
      @rule_index = 0
      @logs = []
      @uri = DEFAULT_URI
    end

    # Retrieve tool section for sarif report
    def build_tool(rules: [])
      {
        "driver": {
          "name" => @scan_report.scanner_name,
          "version" => @scan_report.version,
          "informationUri" => @uri,
          "rules" => rules
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
      if parsed_issue[:code]
        result[:locations][0][:physicalLocation][:region] = {
          "startLine": parsed_issue[:start_line].to_i,
          # "endLine": parsed_issue[:end_line.to_i]
          "snippet": {
            "text": parsed_issue[:code]
          }
        }
      end
      result
    end

    def build_rule(parsed_issue)
      if !@mapped_rules.include?(parsed_issue[:id])
        rule = {
          "id": parsed_issue[:id],
          "name": parsed_issue[:name],
          "fullDescription": {
            "text": parsed_issue[:details]
          },
          "helpUri": parsed_issue[:help_url] || '',
          "help": {
            "text": "More info: #{parsed_issue[:help_url]}",
            "markdown": "[More info](#{parsed_issue[:help_url]})."
          }
        }
        @mapped_rules[parsed_issue[:id]] = @rule_index
        @rule_index += 1
        rule
      end
    end

    # Retrieves invocation object for SARIF report
    def build_invocations
      {
        "executionSuccessful": @scan_report.passed? || false,
        "toolExecutionNotifications": [{
          "descriptor": {
            "id": "SAL001"
          },
          "message": {
            "text": "SARIF reports are not available for this scanner"
          }
        }]
      }
    end

    # Returns the 'runs' object for the scanners report
    def build_runs_object
      results = []
      rules = []
      @logs.each do |issue|
        parsed_issue = parse_issue(issue)
        rule = build_rule(parsed_issue)
        rules << rule if rule
        results << build_result(parsed_issue)
      end

      {
        "tool" => build_tool(rules: rules),
        "conversion" => build_conversion,
        "results" => results,
        "invocations" => [build_invocations]
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
  end
end
