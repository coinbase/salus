module Sarif
  class BrakemanSarif < BaseSarif
    include Salus::SalusBugsnag

    BRAKEMAN_URI = 'https://github.com/presidentbeef/brakeman'.freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = BRAKEMAN_URI
      @logs = parse_scan_report!
    end

    def parse_scan_report!
      logs = @scan_report.log('')
      return [] if logs.strip.empty?

      parsed_result = JSON.parse(logs)
      parsed_result['warnings'].concat(parsed_result['errors'])
    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      []
    end

    def parse_error(error)
      id = error['error'] + ' ' + error['location']
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: SCANNER_ERROR,
        name: "Brakeman Error",
        level: "HIGH",
        details: error['error'],
        uri: error['location'],
        help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md"
      }
    end

    def parse_issue(issue)
      return parse_error(issue) if issue.key?('error')

      {
        id: issue['warning_code'].to_s,
        name: "#{issue['check_name']}/#{issue['warning_type']}",
        level: issue['confidence'].upcase,
        details: (issue['message']).to_s,
        messageStrings: { "title": { "text": (issue['check_name']).to_s },
                          "type": { "text": (issue['warning_type']).to_s },
                          "warning_code": { "text": (issue['warning_code']).to_s } },
        properties: { 'fingerprint': issue['fingerprint'].to_s,
                      'confidence': issue['confidence'].to_s,
                      'severity': "",
                      'render_path': issue['render_path'].to_s,
                      'user_input': issue['user_input'].to_s,
                      'location_type': issue.dig('location', 'type').to_s,
                      'location_class': issue.dig('location', 'class').to_s,
                      'location_method': issue.dig('location', 'method').to_s },
        start_line: issue['line'].to_i,
        start_column: 1,
        uri: issue['file'],
        help_url: issue['link'],
        code: issue['code']
      }
    end
  end
end
