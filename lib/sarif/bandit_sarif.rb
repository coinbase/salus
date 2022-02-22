module Sarif
  class BanditSarif < BaseSarif
    include Salus::SalusBugsnag

    BANDIT_URI = 'https://github.com/PyCQA/bandit'.freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = BANDIT_URI
      @logs = parse_scan_report!
    end

    def parse_scan_report!
      logs = @scan_report.log('')
      return [] if logs.strip.empty?

      parsed_result = JSON.parse(logs)
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
        details: (issue['issue_text']).to_s,
        messageStrings: { "confidence": { "text": (issue['issue_severity']).to_s },
                         "severity": { "text": (issue['issue_severity']).to_s } },
        properties: { 'severity': issue['issue_severity'].to_s },
        start_line: issue["line_number"].to_i,
        end_line: endline,
        start_column: 1,
        uri: issue["filename"],
        help_url: issue['more_info'],
        code: issue['code']
      }
    end

    def self.snippet_possibly_in_git_diff?(snippet, lines_added)
      # Bandit snippet looks like
      #   "2 \n3 self.process = subprocess.Popen('/bin/echo', shell=True)\n4 foo()\n"
      lines = snippet.split("\n")
      # using any? because snippet may include surrounding code that may not be in git diff
      lines.any? do |line|
        line = line.split(' ', 2)[1]
        if line.nil?
          # maybe the line of code has some special pattern
          # we'll just not deal with it and assume snippet may be in git diff
          true
        else
          lines_added.keys.include?(line) && !line.strip.empty?
        end
      end
    end
  end
end
