require 'sarif/package_version/base_sarif'

module Sarif
  class NPMPackageScannerSarif < Sarif::PacakgeVersion::BaseSarif
    def parse_issue(issue)
      parsed_issue = super
      parsed_issue[:name] = "NPMPackageScanner"
      details = parsed_issue[:details][/\{.*?\}/]

      line_number = details&.sub('{', '')&.sub('}', '')
      parsed_issue[:uri] = "package-lock.json"
      if line_number
        parsed_issue[:start_line] = line_number
        parsed_issue[:start_column] = 1
      end
      parsed_issue
    end
  end
end
