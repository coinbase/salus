require 'sarif/package_version/base_sarif'

module Sarif
  class NPMPackageScannerSarif < Sarif::PacakgeVersion::BaseSarif
    def parse_issue(issue)
      details = issue[/\{.*?\}/]
      line_number = details&.sub('{', '')&.sub('}', '')
      super.merge(
        {
          name: "NPMPackageScanner",
          uri: "package-lock.json",
          start_line: line_number.present? ? line_number : "",
          start_column: 1
        }
      )
    end
  end
end
