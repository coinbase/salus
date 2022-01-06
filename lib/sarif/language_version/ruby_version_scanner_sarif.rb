require 'sarif/language_version/base_sarif'

module Sarif
  class RubyVersionScannerSarif < Sarif::LanguageVersion::BaseSarif
    def parse_issue(issue)
      super.merge(
        {
          name: "RubyVersionScanner"
        }
      )
    end
  end
end
