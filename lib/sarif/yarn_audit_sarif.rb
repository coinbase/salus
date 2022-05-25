require 'salus/bugsnag'
module Sarif
  class YarnAuditSarif < BaseSarif
    include Salus::SalusBugsnag
    YARN_URI = 'https://classic.yarnpkg.com/en/docs/cli/audit/'.freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = YARN_URI
      parse_scan_report!
    end

    def parse_scan_report!
      @logs = JSON.parse(@scan_report.to_h[:info][:stdout] || '[]')
    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      @logs = []
    end

    def parse_issue(issue)
      id = issue['ID'].to_s + ' ' + issue['Package'] + ' ' + issue['Dependency of']
      return nil if @issues.include?(id)

      @issues.add(id)
      parsed_issue = {
        id: issue['ID'].to_s,
        name: issue['Title'],
        level: issue['Severity'].upcase,
        details: (issue['Title']).to_s + ", Dependency of: " + issue['Dependency of'],
        messageStrings: { "package": { "text": (issue['Package']).to_s },
                         "severity": { "text": (issue['Severity']).to_s },
                         "patched_versions": { "text": (issue['Patched in']).to_s },
                         "dependency_of": { "text": (issue['Dependency of']).to_s } },
        properties: { 'severity': (issue['Severity']).to_s },
        uri: "yarn.lock",
        help_url: issue['More info']
      }

      if issue.key?("Line number")
        parsed_issue[:start_line] = issue['Line number']
        parsed_issue[:start_column] = 1
        parsed_issue[:code] = issue["Package"]
      end
      parsed_issue
    end

    # fullDescription on a rule should not explain a single vulnerability
    # since multiple vulnerabilites can have the same RuleID
    def build_rule(parsed_issue)
      rule = super(parsed_issue)
      return nil if rule.nil?

      rule[:fullDescription][:text] = rule[:name]
      rule
    end

    def sarif_level(severity)
      case severity
      when "LOW"
        SARIF_WARNINGS[:note]
      when "MODERATE"
        SARIF_WARNINGS[:warning]
      when "HIGH"
        SARIF_WARNINGS[:error]
      when "INFO"
        SARIF_WARNINGS[:note]
      when "CRITICAL"
        SARIF_WARNINGS[:error]
      else
        SARIF_WARNINGS[:note]
      end
    end

    def self.snippet_possibly_in_git_diff?(snippet, lines_added)
      snippet += "@"
      lines_added.keys.any? { |line| line.start_with? snippet }
    end
  end
end
