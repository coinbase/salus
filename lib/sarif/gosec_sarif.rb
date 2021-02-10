module Sarif
  class GosecSarif < BaseSarif
    GOSEC_URI = 'https://github.com/securego/gosec'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = GOSEC_URI
      begin
        json_obj = JSON.parse(scan_report.log(''))
        issues = json_obj['Issues']
        errors = json_obj['Golang errors']
        parsed_errors = []
        errors.each do |key|
          key[1].each do |location|
            location['uri'] = key[0]
            parsed_errors << parse_error(location)
          end
        end
        @logs = issues.concat parsed_errors
      rescue JSON::ParserError
        @logs = []
      end
    end

    def parse_error(error)
      line = error['line'].to_i
      column = error['column'].to_i
      line = 1 if line.zero? 
      column = 1 if column.zero?
      {
        id: 'SAL0002',
        name: "Golang Error",
        level: "NOTE",
        details: error['error'],
        start_line: line,
        start_column: column,
        uri: error['uri'],
        help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md",
        code: ""
      }
    end

    def parse_issue(issue)
      if issue[:id] == 'SAL0002'
        issue
      else
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
    end

    def build_invocations
      error = @scan_report.to_h.fetch(:info)[:stderr]
      if error
        {
          "executionSuccessful": @scan_report.passed?,
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
