require 'salus/bugsnag'

module Sarif
  class TrufflehogSarif < BaseSarif
    include Salus::SalusBugsnag

    SCANNER_URI = 'https://github.com/trufflesecurity/trufflehog'.freeze

    def initialize(scan_report, repo_path = nil, scanner_config = {})
      super(scan_report, {}, repo_path)
      @uri = SCANNER_URI
      @logs = parse_scan_report!(scan_report)
      @scanner_config = scanner_config
    end

    def parse_scan_report!(scan_report)
      data = begin
               logs = scan_report.to_h[:logs] || '[]'
               JSON.parse(logs)
             rescue JSON::ParserError => e
               bugsnag_notify("Trufflehog sarif JSON parse error: " + e.inspect)
               []
             end
      err = scan_report.to_h.dig(:info, :stderr)
      data.push({ scanner_err: err }) if !err.to_s.empty?
      data
    end

    def parse_error(error)
      {
        id: SCANNER_ERROR,
        name: "Trufflehog Scanner Error",
        level: "ERROR",
        details: error[:scanner_err],
        uri: "unknown",
        help_url: @uri
      }
    end

    def parse_issue(issue)
      return parse_error(issue) if issue[:scanner_err]

      # Example issue
      # {"SHA256 of Leaked Credential"=>"REDACTED-SHA",
      # "File"=>"url.txt", "Line Num"=>1, "ID"=>"JDBC-PLAIN", "Verified"=>false}

      {
        id: issue['ID'],
          name: "Leaked credential",
          level: 'HIGH',
          details: "Leaked credential detected",
          messageStrings: { "severity": { "text": 'high' } },
          properties: { 'severity': 'high' },
          start_line: issue['Line Num'],
          start_column: 1,
          uri: issue['File'],
          help_url: @uri,
          code: issue['SHA256 of Leaked Credential']
      }
    end
  end
end
