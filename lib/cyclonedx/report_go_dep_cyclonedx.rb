module Cyclonedx
  class ReportGoDep < Base
    TYPE = "golang".freeze
    UNLOCKED_DEPENDENCY_FILE = "go.mod".freeze
    def initialize(scan_report)
      super(scan_report)
    end
  end
end
