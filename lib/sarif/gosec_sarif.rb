module Sarif
  class GosecSarif < BaseSarif
    GOSEC_URI = 'https://github.com/securego/gosec'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = GOSEC_URI
      begin
        @logs = JSON.parse(scan_report.log(''))['Issues']
      rescue JSON::ParserError
        @logs = []
      end
    end

    def parse_issue(issue)
      {
        id: issue['rule_id'],
        name: "CWE-#{issue['cwe']['ID']}",
        level: issue['severity'],
        details: issue['details'],
        start_line: issue['line'].to_i,
        start_column: issue['column'].to_i,
        uri: issue['file'],
        help_url: issue['cwe']['URL'],
        code: issue['code']
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
