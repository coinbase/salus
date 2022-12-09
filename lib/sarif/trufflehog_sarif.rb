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
          code: issue['Leaked Credential']
      }
    end

    def self.snippet_possibly_in_git_diff?(snippet, lines_added)
=begin
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
=end
    end
  end
end
