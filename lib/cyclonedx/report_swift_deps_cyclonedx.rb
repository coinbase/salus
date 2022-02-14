module Cyclonedx
  class ReportSwiftDeps < Base
    TYPE = "swift".freeze
    UNLOCKED_DEPENDENCY_FILE = "Package.resolved".freeze

    def initialize(scan_report)
      super(scan_report)
    end
  end
end
