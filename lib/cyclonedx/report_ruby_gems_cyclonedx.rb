module Cyclonedx
  class ReportRubyGems < Base
    TYPE = "gem".freeze
    UNLOCKED_DEPENDENCY_FILE = "Gemfile".freeze

    def initialize(scan_report, config = {})
      super(scan_report, config)
    end

    def build_component(dependency)
      super.merge({
                    "licenses": licenses_for(dependency)
                  })
    end

    def licenses_for(dependency)
      return [] if dependency[:licenses].nil?

      dependency[:licenses].map { |license| { "license" => { "id" => license } } }
    end
  end
end
