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
          "name" => scan_report.scanner_name,
          "version" => scan_report.version || ""
        }
      }
    end

    # Retrieves result section for sarif report
    def results_info
      []
    end

    # Retrieves invocation object for SARIF report
    def invocations
      body = []
      default = {
        "executionSuccessful": @scan_report.passed? || false,
        "toolExecutionNotifications": [{
          "descriptor": {
            "id": "SAL001"
          },
          "message": {
            "text": "Salus does yet support SARIF details for this scanner"
          }
        }]
      }
      body << default
    end

    # Returns the 'runs' object for the scanners report
    def sarif_report
      {
        "tool" => @tool,
        "conversion" => conversion,
        "results" => @results,
        "invocations" => invocations
      }
    end

    # Returns the conversion object for the SARIF report
    def conversion
      {
        "tool": {
          "driver": {
            "name": "Salus",
            "informationUri": DEFAULT_URI
          }
        }
      }
    end
  end
end
