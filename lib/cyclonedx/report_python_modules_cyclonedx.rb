module Cyclonedx
  class ReportPythonModules < Base
    def initialize(scan_report)
      super(scan_report)
    end

    def package_url(dependency)
      "pkg:#{dependency[:type]}/#{dependency[:name]}#{version_string(dependency, true)}"
    end

    # Return version string to be used in purl or component
    def version_string(dependency, is_purl_version = false)
      # Check if dependency is pinned
      is_pinned = !!dependency[:version].match(/^==[0-9]/)

      # If unpinned dependency is specified in requirements.txt
      # and version is needed for purl
      if dependency[:dependency_file] == 'requirements.txt' && is_purl_version && !is_pinned
        return ""
      end

      prefix = is_purl_version ? "@" : ""

      # Will only gsub if absolute/pinned dependency version
      return "#{prefix}#{dependency[:version]}" unless is_pinned

      "#{prefix}#{dependency[:version].gsub(/^==/, '')}"
    end
  end
end
