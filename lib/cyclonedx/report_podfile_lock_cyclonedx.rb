module Cyclonedx
  class ReportPodfileLock < Base
    TYPE = "cocoa".freeze
    UNLOCKED_DEPENDENCY_FILE = "Podfile".freeze

    def initialize(scan_report)
      super(scan_report)
    end
  end
end
