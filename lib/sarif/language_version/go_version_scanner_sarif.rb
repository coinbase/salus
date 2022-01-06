require 'sarif/language_version/base_sarif'

module Sarif
  class GoVersionScannerSarif < Sarif::LanguageVersion::BaseSarif
    def parse_issue(issue)
      super.merge(
        {
          name: "GoVersionScanner"
        }
      )
    end
  end
end
