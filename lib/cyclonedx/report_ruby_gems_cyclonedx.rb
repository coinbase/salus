module Cyclonedx
  class ReportRubyGems < Base
    TYPE = "gem".freeze
    UNLOCKED_DEPENDENCY_FILE = "Gemfile".freeze

    def initialize(scan_report, config = {})
      super(scan_report, config)
    end
  end
end
