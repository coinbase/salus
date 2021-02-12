module Sarif
  class BundleAuditSarif < BaseSarif
    BUNDLEAUDIT_URI = 'https://github.com/securego/gosec'.freeze

    def initialize(scan_report)
      super(scan_report)
      @logs = @scan_report.to_h[:info][:vulnerabilities]
      @uri = BUNDLEAUDIT_URI
    end

    def parse_issue(issue)
      {
        id: issue[:cve],
        name: issue[:advisory_title],
        level: "MEDIUM",
        details: issue[:description],
        uri: 'Gemfile.lock',
        help_url: issue[:url]
      }
    end
  end
end
