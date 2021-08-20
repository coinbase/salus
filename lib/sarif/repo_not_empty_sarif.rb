require 'salus/bugsnag'

module Sarif
  class RepoNotEmptySarif < BaseSarif
    include Salus::SalusBugsnag

    REPO_NOT_EMPTY_URI = "https://github.com/coinbase/salus/blob/master/docs/scanners/"\
    "repository_not_blank.md".freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = REPO_NOT_EMPTY_URI
      @logs = parse_scan_report!
    end

    def parse_scan_report!
      @scan_report.errors
    end

    def parse_issue(issue)
      {
        id: "RNE0001",
        name: "RepositoryIsEmpty",
        details: issue[:message],
        level: "HIGH",
        uri: "",
        help_url: REPO_NOT_EMPTY_URI
      }
    end
  end
end
