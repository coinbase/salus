module Salus::Scanners
  # Super class for all scanner objects.
  class ReportBase < Base
    def is_reporting_scanner?
      true
    end
  end
end
