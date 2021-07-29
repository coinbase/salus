module Cyclonedx
  class ReportRubyGems < Base
    def initialize(scan_report)
      super(scan_report)
    end

    def package_url(dependency)
      "pkg:#{dependency[:type]}/#{dependency[:name]}#{version_string(dependency)}"
    end

    # Return version string to be used in purl
    def version_string(dependency)
      if dependency[:dependency_file] == 'Gemfile.lock'
        # Return empty string if concrete dependency version specified in Gemfile.lock
        "@#{dependency[:version]}"
      else
        ""
      end
    end
  end
end
