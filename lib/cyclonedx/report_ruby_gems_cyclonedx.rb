module Cyclonedx
  class ReportRubyGems < Base
    def initialize(scan_report)
      super(scan_report)
    end

    def package_url(dependency)
      "pkg:#{dependency[:type]}/#{dependency[:name]}#{version_string(dependency, true)}"
    end

    # Return version string to be used in purl
    def version_string(dependency, is_purl_version = false)
      prefix = is_purl_version ? "@" : ""
      if dependency[:dependency_file] == 'Gemfile.lock'
        # Return concrete dependency version specified in Gemfile.lock
        "#{prefix}#{dependency[:version]}"
      else
        ""
      end
    end
  end
end
