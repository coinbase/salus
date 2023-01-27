require 'salus/bugsnag'

module Sarif::LanguageVersion
  class BaseSarif < Sarif::BaseSarif
    include Salus::SalusBugsnag

    LANGUAGE_VERSION_DOC_URI = "https://github.com/coinbase/salus/blob/master/docs/scanners/"\
    "language_version_scan.md".freeze

    LANGUAGE_VERSION_MISMATCH = "LV0001".freeze
    SEVERITY = "HIGH".freeze

    def initialize(scan_report, repo_path = nil, scanner_config = {})
      super(scan_report, {}, repo_path)
      @uri = LANGUAGE_VERSION_DOC_URI
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
      {
        id: LANGUAGE_VERSION_MISMATCH,
        name: "LanguageVersion",
        details: issue,
        level: SEVERITY,
        uri: "",
        help_url: LANGUAGE_VERSION_DOC_URI,
        properties: { severity: SEVERITY }
      }
    end
  end
end
