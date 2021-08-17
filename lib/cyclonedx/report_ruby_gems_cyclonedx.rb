module Cyclonedx
  class ReportRubyGems < Base
    TYPE = "gem".freeze

    def initialize(scan_report, config = {})
      super(scan_report, config)
    end

    # Return version string to be used in purl or component
    def version_string(dependency, is_purl_version = false)
      # If the dependency is specified in the Gemfile and an absolute version is needed for
      # the purl return empty
      return "" if dependency[:dependency_file] == 'Gemfile' && is_purl_version

      dependency[:version]
    end
  end
end
