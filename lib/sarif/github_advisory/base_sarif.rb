require 'salus/bugsnag'

module Sarif::GithubAdvisory
  class BaseSarif < Sarif::BaseSarif
    include Salus::SalusBugsnag

    GITHUB_ADVISORY_URI = "https://github.com/advisories/".freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = GITHUB_ADVISORY_URI
      @logs = parse_scan_report!
    end

    def parse_scan_report!
      logs = []
      advisories = @scan_report.to_h.dig(:logs).split("\n\n")
      advisories.each do |advisory|
        doc = {}
        document = advisory.split("\n")
        document.each do |d|
          key, value = d.split(":", 2)
          doc[key] = value.to_s.strip
        end
        logs.append(doc)
      end
      return [] if logs.empty?

      logs
    end

    def parse_issue(issue)
      parsed_issue = {
        id: issue['ID'],
          name: issue['Summary'],
          level: issue['Severity'],
          details: issue['Summary'],
          messageStrings: { "package": { "text": issue['Package'] },
                           "title": { "text": issue['Summary'] },
                           "severity": { "text": issue['Severity'] },
                           "patched_versions": { "text": issue['Patched Versions'] },
                           "vulnerable_versions": {
                             "text": issue['Vulnerable Version']
                           } },
          properties: { 'severity': issue['Severity'] },
          uri: GITHUB_ADVISORY_URI,
          help_url: GITHUB_ADVISORY_URI + issue['ID']
      }

      parsed_issue
    end
  end
end
