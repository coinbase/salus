require 'salus/bugsnag'

module Sarif::OSV
  class BaseSarif < Sarif::BaseSarif
    include Salus::SalusBugsnag

    OSV_URI = "https://osv.dev/list".freeze
    SCANNER_NAME = "OSV Scanner".freeze

    def initialize(scan_report, repo_path = nil, scanner_config = {})
      super(scan_report, {}, repo_path)
      @uri = OSV_URI
      @logs = parse_scan_report!
      @scanner_config = scanner_config
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
      # Example issue
      # {"Package"=>"github.com/syncthing/syncthing",
      # "Vulnerable Version"=>"0",
      # "Version Detected"=>"1.14.0",
      # "Patched Version"=>"1.15.0",
      # "ID"=>"CVE-2021-21404",
      # "Database"=>"Github Advisory Database",
      # "Summary"=>"Crash due to malformed relay protocol message",
      # "References"=>
      #  "https://github.com/advisories/GHSA-x462-89pf-6r5h, https://nvd.nist.gov...",
      # "Source"=>"https://osv.dev/list",
      # "Severity"=>"LOW"}

      parsed_issue = {
        id: issue['ID'],
          name: SCANNER_NAME,
          level:  issue['Severity'],
          details: issue['Summary'].to_s,
          messageStrings: { "package": { "text": issue['Package'].to_s },
                           "title": { "text": issue['Summary'].to_s },
                           "severity": { "text": issue['Severity'].to_s },
                           "cwe": { "text": [issue['ID']].to_s },
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
