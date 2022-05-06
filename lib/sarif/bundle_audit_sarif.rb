module Sarif
  class BundleAuditSarif < BaseSarif
    BUNDLEAUDIT_URI = 'https://github.com/rubysec/bundler-audit/'.freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @logs = @scan_report.to_h.dig(:info, :vulnerabilities) || []
      @uri = BUNDLEAUDIT_URI
    end

    def parse_issue(issue)
      result = {
        id: issue[:cve] || issue[:osvdb].to_s,
        name: issue[:advisory_title],
        level: issue[:cvss].to_i,
        details: (issue[:description]).to_s,
        messageStrings: { "package_name": { "text": (issue[:name]).to_s },
                         "severity": { "text": (issue[:cvss]).to_s },
                         "patched_versions": { "text": (issue[:patched_versions]).to_s },
                         "unaffected_versions": { "text": (issue[:unaffected_versions]).to_s },
                         "title": { "text": (issue[:advisory_title]).to_s },
                         "osvdb": { "text": (issue[:osdvb]).to_s },
                         "type": { "text": (issue[:type]).to_s },
                         "version": { "text": (issue[:version]).to_s } },
        properties: { 'severity': (issue[:cvss]).to_s },
        uri: 'Gemfile.lock',
        help_url: issue[:url]
      }
      if issue[:line_number]
        result[:start_line] = issue[:line_number]
        result[:start_column] = 1
        result[:code] = issue[:name].to_s # Code stores the gem name without version in snippet
      end

      if issue[:type] == "InsecureSource"
        result[:id] = issue[:type]
        result[:name] = issue[:type] + ' ' + issue[:source]
        result[:details] = "Type: #{issue[:type]}\nSource: #{issue[:source]}"
      end

      result
    end

    def sarif_level(severity)
      case severity
      when 0.0..3.9
        SARIF_WARNINGS[:note]
      when 4.0..6.9
        SARIF_WARNINGS[:warning]
      when 7.0..10.0
        SARIF_WARNINGS[:error]
      end
    end

    def self.snippet_possibly_in_git_diff?(snippet, lines_added)
      # snippet in sarif just has the package name (without spaces/version)
      # actual snippet in Gemfile.lock looks like " nokogiri (>= 1.5.11, < 2.0.0)"
      snippet = ' ' + snippet + ' ('
      lines_added.keys.any? { |line| line.include? snippet }
    end
  end
end
