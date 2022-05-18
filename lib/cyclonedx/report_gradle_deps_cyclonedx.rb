module Cyclonedx
  class ReportGradleDeps < Base
    TYPE = "gradle".freeze
    UNLOCKED_DEPENDENCY_FILE = "build.gradle".freeze
  end
end
