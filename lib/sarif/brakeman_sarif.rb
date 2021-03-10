module Sarif
  class BrakemanSarif < BaseSarif
    include Salus::SalusBugsnag

    BRAKEMAN_URI = 'https://github.com/presidentbeef/brakeman'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = BRAKEMAN_URI
      @logs = parse_scan_report!
    end

    def parse_scan_report!
      JSON.parse(@scan_report.log(''))['warnings']
    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      []
    end

    def parse_issue(issue)
      {
        id: issue['warning_code'],
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
  end
end
