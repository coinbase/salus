module Cyclonedx
  class ReportPythonModules < Base
    TYPE = "pypi".freeze
    UNLOCKED_DEPENDENCY_FILE = "requirements.txt".freeze

    def initialize(scan_report)
      super(scan_report)
    end

    def build_component(dependency)
      super.merge({
                    "licenses": licenses_for(dependency)
                  })
    end

    def licenses_for(dependency)
      return [] if dependency[:licenses].nil?

      dependency[:licenses].map { |license| { "license": { "id" => license } } }
    end

    # Return version string to be used in purl or component
    def version_string(dependency, is_purl_version = false)
      # Check if dependency is pinned
      is_pinned = !!dependency[:version].match(/^==[0-9]/)

      # If unpinned dependency is specified in requirements.txt
      # and version is needed for purl
      if dependency[:dependency_file] == UNLOCKED_DEPENDENCY_FILE &&
          is_purl_version && !is_pinned
        return ""
      end

      # Will only gsub if absolute/pinned dependency version
      return dependency[:version] unless is_pinned

      dependency[:version].gsub(/^==/, '')
    end
  end
end
