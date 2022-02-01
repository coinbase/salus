module Cyclonedx
  class ReportPomXml < Base
    TYPE = "maven".freeze
    UNLOCKED_DEPENDENCY_FILE = "pom.xml".freeze

    def initialize(scan_report)
      super(scan_report)
    end
  end
end
