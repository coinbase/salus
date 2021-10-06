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
  end
end
