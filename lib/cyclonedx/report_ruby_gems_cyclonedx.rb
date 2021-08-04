module Cyclonedx
  class ReportRubyGems < Base
    def initialize(scan_report)
      super(scan_report)
    end

    def package_url(dependency)
      "pkg:#{dependency[:type]}/#{dependency[:name]}#{version_string(dependency, true)}"
    end

    # Return version string to be used in purl or component
    def version_string(dependency, is_purl_version = false)
      # If the dependency is specified in the Gemfile and an absolute version is needed for
      # the purl return empty
      return "" if dependency[:dependency_file] == 'Gemfile' && is_purl_version

      prefix = is_purl_version ? "@" : ""
      "#{prefix}#{dependency[:version]}"
    end
  end
end
