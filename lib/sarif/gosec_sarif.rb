require 'salus/bugsnag'

module Sarif
  class GosecSarif < BaseSarif
    include Salus::SalusBugsnag

    GOSEC_URI = 'https://github.com/securego/gosec'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = GOSEC_URI
      @logs = parse_scan_report!(scan_report)
    end

    def parse_scan_report!(scan_report)
      log = scan_report.log("")
      if !log.size.zero?
        json_obj = JSON.parse(log)
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
      else
        []
      end
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

        @issues.add(id)
        {
          id: issue['rule_id'],
          name: "CWE-#{issue['cwe']['ID']}",
          level: issue['severity'],
          details: "#{issue['details']} \nSeverity: #{issue['severity']}\nConfidence:"\
          " #{issue['confidence']}\nCWE: #{issue['cwe']['URL']}",
          start_line: issue['line'].to_i,
          start_column: issue['column'].to_i,
          uri: issue['file'],
          help_url: issue['cwe']['URL'],
          code: issue['code']
        }
      end
    end
  end
end
