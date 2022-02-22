require 'salus/bugsnag'
require 'pathname'

module Sarif
  class GosecSarif < BaseSarif
    include Salus::SalusBugsnag

    GOSEC_URI = 'https://github.com/securego/gosec'.freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = GOSEC_URI
      @logs = parse_scan_report!(scan_report)
    end

    def parse_scan_report!(scan_report)
      logs = scan_report.log('')
      return [] if logs.strip.empty?

      json_obj = JSON.parse(logs)
      issues = json_obj['Issues']
      errors = json_obj['Golang errors']
      parsed_errors = []
      errors.each do |key|
        key[1].each do |location|
          location['uri'] = key[0]
          parsed_errors << parse_error(location)
        end
      end
      parsed_errors.compact!
      issues.concat parsed_errors
    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      []
    end

    def parse_error(error)
      line = error['line'].to_i
      column = error['column'].to_i
      line = 1 if line.zero?
      column = 1 if column.zero?

      id = error['error'] + ' ' + error['uri'] + ' ' + line.to_s
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: SCANNER_ERROR,
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
      if issue[:id] == SCANNER_ERROR
        issue
      else
        id = issue['details'] + ' ' + issue['file'] + ' ' + issue['line']
        return nil if @issues.include?(id)

        # Newer gosecs have changed case to lower. Preparing to upgrade,
        # we'll support both
        url = issue['cwe']['URL'] || issue['cwe']['url']
        id = issue['cwe']['ID'] || issue['cwe']['id']
        filepath = Pathname.new(issue['file'])

        uri = if filepath.relative? || base_path.nil?
                filepath.to_s
              else
                filepath.relative_path_from(base_path).to_s
              end

        @issues.add(id)
        {
          id: issue['rule_id'],
          name: "CWE-#{id}",
          level: issue['severity'],
          details: "#{issue['details']} \nSeverity: #{issue['severity']}\nConfidence:"\
          " #{issue['confidence']}\nCWE: #{url}",
          messageStrings: { "severity": { "text": (issue['severity']).to_s },
                           "confidence": { "text": (issue['confidence']).to_s },
                           "cwe": { "text": url.to_s } },
          properties: { 'severity': (issue['severity']).to_s },
          start_line: issue['line'].to_i,
          start_column: issue['column'].to_i,
          uri: uri,
          help_url: url,
          code: issue['code']
        }
      end
    end

    def self.snippet_possibly_in_git_diff?(snippet, lines_added)
      lines = snippet.split("\n")
      # using any? because Gosec snippet contains surrounding code, which
      # may not be in git diff
      lines.any? do |line|
        # split by ": " because Gosec snippet has the form
        #    "$line_number: $code\n$line_number: $code\n$line_number: $code..."
        line = line.split(': ', 2)[1]
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
