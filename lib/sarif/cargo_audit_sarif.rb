module Sarif
  class CargoAuditSarif < BaseSarif
    CARGO_AUDIT_URI = 'https://github.com/RustSec/cargo-audit/'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = CARGO_AUDIT_URI
      begin
        x = JSON.parse(scan_report.log(''))
        vulnerabilities = x['vulnerabilities']['list']
        unmaintained = x['warnings']['unmaintained'] || []
        @logs = vulnerabilities.concat unmaintained
      rescue JSON::ParserError
        @logs = []
      end
    end

    def parse_issue(issue)
      {
        id: issue['advisory']['id'],
        name: issue['advisory']['title'],
        level: issue['kind'] || "HIGH",
        details: issue['advisory']['description'],
        uri: 'Cargo.lock',
        help_url: issue['advisory']['url']
      }
    end

    def build_invocations
      if @logs.empty? && !@scan_report.passed?
        error = @scan_report.to_h.fetch(:info)[:stderr]
        {
          "executionSuccessful": false,
          "toolExecutionNotifications": [{
            "descriptor": {
              "id": ""
            },
            "level": "error",
            "message": {
              "text": "#{@scan_report.to_h.fetch(:errors).first[:message] || ''}, #{error}"
            }
          }]
        }
      else
        { "executionSuccessful": @scan_report.passed? }
      end
    end
  end
end
