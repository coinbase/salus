module Sarif
  class BrakemanSarif < BaseSarif
    BRAKEMAN_URI = 'https://github.com/presidentbeef/brakeman'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = BRAKEMAN_URI
      begin
        @logs = JSON.parse(scan_report.log(''))['warnings']
      rescue JSON::ParserError
        @logs = []
      end
    end

    def parse_issue(issue)
      {
        id: format('BRAKE%<number>.4d', number: issue['warning_code'].to_i),
        name: "#{issue['check_name']}/#{issue['warning_type']}",
        level: issue['confidence'].upcase,
        details: issue['message'],
        start_line: issue['line'].to_i,
        start_column: 1,
        uri: issue['file'],
        help_url: issue['link'],
        code: issue['code']
      }
    end

    def build_invocations
      if @logs.empty? && !@scan_report.passed?
        {
          "executionSuccessful": false,
          "toolExecutionNotifications": [{
            "descriptor": {
              "id": ""
            },
            "level": "error",
            "message": {
              "text": @scan_report.to_h.fetch(:errors).first[:message]
            }
          }]
        }
      else
        { "executionSuccessful": @scan_report.passed? }
      end
    end
  end
end
