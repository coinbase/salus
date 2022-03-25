require 'salus/bugsnag'

module Sarif::PacakgeVersion
  class BaseSarif < Sarif::BaseSarif
    include Salus::SalusBugsnag

    PACKAGE_VERSION_DOC_URI = "https://github.com/coinbase/salus/blob/master/docs/scanners/"\
    "package_version_scan.md".freeze

    PACKAGE_VERSION_MISMATCH = "PV0001".freeze
    SEVERITY = "HIGH".freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = PACKAGE_VERSION_DOC_URI
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
      {
        id: PACKAGE_VERSION_MISMATCH,
        name: "PackageVersion",
        details: issue,
        level: SEVERITY,
        uri: "",
        help_url: PACKAGE_VERSION_DOC_URI,
        properties: { severity: SEVERITY }
      }
    end

    def build_rule(parsed_issue)
      rule = super
      rule[:fullDescription][:text] = "Package version does not fall within specified range" if rule
      rule
    end
  end
end
