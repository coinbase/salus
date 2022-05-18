module Cyclonedx
  class ReportGoDep < Base
    TYPE = "golang".freeze
    UNLOCKED_DEPENDENCY_FILE = "go.mod".freeze
  end
end
