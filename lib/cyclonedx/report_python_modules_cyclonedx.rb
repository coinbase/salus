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
      # Duplicate for the second time this is called in base.rb for the purl field
      # Prevents any issues with the initial gsub for the first call
      dummy_version = dependency[:version].dup
      # Check if dependency is pinned
      is_pinned = !!dummy_version.match(/^==[0-9]/)

      # If unpinned dependency is specified in requirements.txt
      # and version is needed for purl
      if dependency[:dependency_file] == 'requirements.txt' && is_purl_version && !is_pinned
        return ""
      end

      prefix = is_purl_version ? "@" : ""

      # Will only gsub if absolute/pinned dependency version
      if is_pinned
        dummy_version.gsub!(/^==/, '')
        "#{prefix}#{dummy_version}"
      else
        "#{prefix}#{dependency[:version]}"
      end
    end
  end
end
