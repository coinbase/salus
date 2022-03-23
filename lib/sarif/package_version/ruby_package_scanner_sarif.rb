require 'sarif/package_version/base_sarif'

module Sarif
  class RubyPackageScannerSarif < Sarif::PacakgeVersion::BaseSarif
    def parse_issue(issue)
      super.merge(
        {
          name: "RubyPackageScanner",
          uri: "Gemfile.lock"
        }
      )
    end
  end
end
