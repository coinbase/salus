require 'salus/bugsnag'

module Sarif::LanguageVersion
  class BaseSarif < Sarif::BaseSarif
    include Salus::SalusBugsnag

    LANGUAGE_VERSION_DOC_URI = "https://github.com/coinbase/salus/blob/master/docs/scanners/"\
    "language_version_scan.md".freeze

    LANGUAGE_VERSION_MISMATCH = "LV0001".freeze
    SEVERITY = "HIGH".freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = LANGUAGE_VERSION_DOC_URI
      @logs = parse_scan_report!
    end

    def parse_scan_report!
      @scan_report.errors
    end

    def parse_issue(issue)
      {
        id: LANGUAGE_VERSION_MISMATCH,
        name: "LanguageVersion",
        details: issue[:message],
        level: SEVERITY,
        uri: "",
        help_url: LANGUAGE_VERSION_DOC_URI,
        properties: { severity: SEVERITY }
      }
    end
  end
end
