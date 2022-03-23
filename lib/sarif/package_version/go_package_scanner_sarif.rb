require 'sarif/package_version/base_sarif'

module Sarif
  class GoPackageScannerSarif < Sarif::PacakgeVersion::BaseSarif
    def parse_issue(issue)
      super.merge(
        {
          name: "GoPackageScanner",
          uri: "go.sum"
        }
      )
    end
  end
end
