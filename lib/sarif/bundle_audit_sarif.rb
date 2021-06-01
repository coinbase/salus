module Sarif
  class BundleAuditSarif < BaseSarif
    BUNDLEAUDIT_URI = 'https://github.com/rubysec/bundler-audit/'.freeze

    def initialize(scan_report)
      super(scan_report)
      @logs = @scan_report.to_h.dig(:info, :vulnerabilities) || []
      @uri = BUNDLEAUDIT_URI
    end

    def parse_issue(issue)
      result = {
        id: issue[:cve] || issue[:osvdb].to_s,
        name: issue[:advisory_title],
        level: issue[:cvss].to_i,
        details: "Package Name: #{issue[:name]}\nType: #{issue[:type]}\nVersion: "\
        "#{issue[:version]}\n Advisory Title: #{issue[:advisory_title]}\nDesciption: "\
        "#{issue[:description]}\nPatched Versions: #{issue[:patched_versions]}"\
        "\nUnaffected Versions: #{issue[:unaffected_versions]}\nCVSS: #{issue[:cvss]}"\
        "\nOSVDB #{issue[:osdvb]}",
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
