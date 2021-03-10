module Sarif
  module SharedObjects
    def build_invocations(scan_report, supported)
      if supported
        supported_scanner_invocation(scan_report)
      else
        unsupported_scanner_invocation(scan_report)
      end
    end

    # Invocation object for an unsupported scanner
    def unsupported_scanner_invocation(scan_report)
      {
        "executionSuccessful": scan_report.passed?,
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

    def supported_scanner_invocation(scan_report)
      error = scan_report.to_h[:errors]
      if !error.empty?
        {
          "executionSuccessful": scan_report.passed?,
          "toolExecutionNotifications": [{
            "descriptor": {
              "id": "SAL003"
            },
            "level": "error",
            "message": {
              "text": "==== Salus Errors\n#{JSON.pretty_generate(error)}"
            }
          }]
        }
      else
        { "executionSuccessful": scan_report.passed? }
      end
    end
  end
end
