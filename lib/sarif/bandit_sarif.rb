module Sarif
  class BanditSarif < BaseSarif
    BANDIT_URI = 'https://github.com/PyCQA/bandit'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = BANDIT_URI
      begin
        @logs = JSON.parse(@scan_report.log(''))['results']
      rescue JSON::ParserError
        @logs = []
      end
      @unique_issues = Set.new
    end

    def parse_issue(issue)
      key = ""
      key << issue["filename"].upcase + issue["line_number"].to_s + issue['issue_text']
      return nil if @unique_issues.include? key

      @unique_issues.add(key)
      endline = issue['line_range'][issue['line_range'].size - 1]
      {
        id: issue['test_id'],
        name: issue['test_name'],
        level: issue['issue_severity'],
        details: "#{issue['issue_text']} \nissue_confidence: #{issue['issue_severity']}"\
        "\nissue_severity: #{issue['issue_severity']}",
        start_line: issue["line_number"].to_i,
        end_line: endline,
        start_column: 1,
        uri: issue["filename"],
        help_url: issue['more_info'],
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
