module Cyclonedx
  class ReportGradleDeps < Base
    TYPE = "gradle".freeze
    UNLOCKED_DEPENDENCY_FILE = "build.gradle".freeze

    def initialize(scan_report)
      super(scan_report)
    end
  end
end
