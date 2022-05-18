module Cyclonedx
  class ReportSwiftDeps < Base
    TYPE = "swift".freeze
    UNLOCKED_DEPENDENCY_FILE = "Package.resolved".freeze
  end
end
