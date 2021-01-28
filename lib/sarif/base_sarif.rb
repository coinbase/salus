module Sarif
  class BaseSarif
    DEFAULT_URI = "https://github.com/coinbase/salus".freeze

    attr_reader :name, :tool, :results, :scan_report
    def initialize(scan_report)
      @name = scan_report.scanner_name
      @scan_report = scan_report
      @tool = tool_info
      @results = results_info
    end

    # Retrieve tool section for sarif report
    def tool_info
      {
        "driver": {
          "name" => @scan_report.scanner_name,
          "semanticVersion" => @scan_report.version || "",
          "informationUri" => DEFAULT_URI
        }
      }
    end

    # Retreives result section for sarif report
    def results_info
      {
        "ruleId"  => "SALUS001",
        "message" => {
          "text": "This Scanner does not currently Support SARIF"
        }
      }
    end

    # Returns 'runs' object for the scanners report
    def sarif_report
      {
        "tool" => @tool,
        "result" => @results
      }
    end
  end
end
