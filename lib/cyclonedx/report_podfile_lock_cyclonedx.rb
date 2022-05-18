module Cyclonedx
  class ReportPodfileLock < Base
    TYPE = "cocoapods".freeze
    UNLOCKED_DEPENDENCY_FILE = "Podfile".freeze
  end
end
