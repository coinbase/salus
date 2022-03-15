require 'sarif/package_version/base_sarif'

module Sarif
  class GoPackageScannerSarif < Sarif::PacakgeVersion::BaseSarif
    def parse_issue(issue)
      parsed_issue = super
      parsed_issue[:name] = "GoPackageScanner"
      parsed_issue[:uri] = "go.sum"
      parsed_issue
    end
  end
end
