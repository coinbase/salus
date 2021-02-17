module Sarif
  class BundleAuditSarif < BaseSarif
    BUNDLEAUDIT_URI = 'https://github.com/securego/gosec'.freeze

    def initialize(scan_report)
      super(scan_report)
      @logs = @scan_report.to_h[:info][:vulnerabilities]
      @uri = BUNDLEAUDIT_URI
      @urls = Set.new
    end

    def parse_issue(issue)
      return nil if @urls.include?(issue[:url])

      @urls.add(issue[:url])
      {
        id: issue[:cve],
        name: issue[:advisory_title],
        level: "MEDIUM",
        details: "Name: #{issue[:name]}\nVersion: #{issue[:version]}\nDesciption: "\
        "#{issue[:description]}\nPatched Versions: #{issue[:patched_versions]}",
        uri: 'Gemfile.lock',
        help_url: issue[:url]
      }
    end

    def build_invocations
      { "executionSuccessful": @scan_report.passed? || false }
    end
  end
end
