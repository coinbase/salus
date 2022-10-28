require 'salus/scanners/base'

module Salus::Scanners
  # Super class for all scanner objects.
  class ReportBase < Base
    def self.scanner_type
      Salus::ScannerTypes::SBOM_REPORT
    end
  end
end
