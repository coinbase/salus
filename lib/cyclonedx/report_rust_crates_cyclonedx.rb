module Cyclonedx
  class ReportRustCrates < Base
    TYPE = "cargo".freeze
    UNLOCKED_DEPENDENCY_FILE = "".freeze

    def initialize(scan_report)
      super(scan_report)
    end
  end
end
