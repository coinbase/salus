module Cyclonedx
  class ReportGradleDeps < Base
    TYPE = "gradle".freeze
    UNLOCKED_DEPENDENCY_FILE = "gradle.lockfile".freeze

    def initialize(scan_report)
      super(scan_report)
    end
  end
end
