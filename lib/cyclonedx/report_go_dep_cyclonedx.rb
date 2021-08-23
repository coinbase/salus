module Cyclonedx
  class ReportGoDep < Base
    TYPE = "golang".freeze
    UNLOCKED_DEPENDENCY_FILE = "go.sum".freeze
    def initialize(scan_report)
      super(scan_report)
    end

    # Return version string to be used in purl or component
    def version_string(dependency, is_purl_version = false)
      # If the dependency is specified in a unlocked dependency file and an absolute version
      # is needed for the purl return empty
      if (dependency[:dependency_file] == self.class::UNLOCKED_DEPENDENCY_FILE ||
          dependency[:dependency_file] == "Gopkg.lock") && is_purl_version
        return ""
      end

      dependency[:version]
    end
  end
end
