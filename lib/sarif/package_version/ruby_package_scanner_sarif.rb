require 'sarif/package_version/base_sarif'

module Sarif
  class RubyPackageScannerSarif < Sarif::PacakgeVersion::BaseSarif
    def parse_issue(issue)
      parsed_issue = super
      parsed_issue[:name] = "RubyPackageScanner"
      parsed_issue[:uri] = "Gemfile.lock"
      parsed_issue
    end
  end
end
