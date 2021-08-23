module Cyclonedx
  class ReportRustCrates < Base
    TYPE = "cargo".freeze

    def initialize(scan_report)
      super(scan_report)
    end
  end
end
