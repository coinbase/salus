require 'salus/bugsnag'

module Sarif::OSV
  class BaseSarif < Sarif::BaseSarif
    include Salus::SalusBugsnag

    OSV_URI = "https://osv.dev/list".freeze
    SCANNER_NAME = "OSV Scanner".freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = OSV_URI
      @logs = parse_scan_report!
    end

    def parse_scan_report!
      logs = @scan_report.log('')
      return [] if logs.strip.empty?

      JSON.parse(@scan_report.to_h.dig(:logs))
    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      []
    end

    def parse_issue(issue)
      parsed_issue = {
        id: issue['ID'],
          name: SCANNER_NAME,
          level:  issue['Severity'],
          details: issue['Summary'].to_s,
          messageStrings: { "package": { "text": issue['Package'].to_s },
                           "title": { "text": issue['Summary'].to_s },
                           "severity": { "text": issue['Severity'].to_s },
                           "patched_versions": { "text": issue['Patched Version'].to_s },
                           "vulnerable_versions": {
                             "text": issue['Vulnerable Version'].to_s
                           } },
          properties: { 'severity': issue['Severity'] },
          uri: OSV_URI.to_s,
          help_url: issue["Source"].to_s
      }

      parsed_issue
    end
  end
end
