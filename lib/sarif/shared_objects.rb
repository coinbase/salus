module Sarif
  module SharedObjects
    UNSUPPORTED_SCANNER = 'SAL001'.freeze # Scanner currently has no sarif adapters
    SCANNER_ERROR = 'SAL002'.freeze # Errors logged in a scanners json report
    SALUS_SCANNER_ERROR = 'SAL003'.freeze # Errors logged by scanner during invocation

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
            "id": UNSUPPORTED_SCANNER
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
              "id": SALUS_SCANNER_ERROR
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
