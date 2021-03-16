module Sarif
  class BanditSarif < BaseSarif
    include Salus::SalusBugsnag

    BANDIT_URI = 'https://github.com/PyCQA/bandit'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = BANDIT_URI
      @logs = parse_scan_report!
    end

    def parse_scan_report!
      parsed_result = JSON.parse(@scan_report.log(''))

      parsed_result['results'].concat(parsed_result['errors'])
    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      []
    end

    def parse_error(error)
      id = error['filename'] + ' ' + error['reason']
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: SCANNER_ERROR,
        name: "Bandit Error",
        level: "HIGH",
        details: error['reason'],
        uri: error['filename'],
        help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md"
      }
    end

    def parse_issue(issue)
      return parse_error(issue) if !issue.key?('issue_text')

      key = issue["filename"] + ' ' + issue["line_number"].to_s + ' ' + issue['issue_text']
      return nil if @issues.include? key

      @issues.add(key)
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
  end
end
