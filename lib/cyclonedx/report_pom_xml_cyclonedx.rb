module Cyclonedx
  class ReportPomXml < Base
    TYPE = "maven".freeze
    UNLOCKED_DEPENDENCY_FILE = "pom.xml".freeze
  end
end
