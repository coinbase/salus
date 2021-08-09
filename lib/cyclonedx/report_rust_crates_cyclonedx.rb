module Cyclonedx
  class ReportRustCrates < Base
    def initialize(scan_report)
      super(scan_report)
    end

    def package_url(dependency)
      "pkg:#{dependency[:type]}/#{dependency[:name]}@#{version_string(dependency)}"
    end

    # Return version string to be used in purl or component
    def version_string(dependency)
      (dependency[:version_tag]).to_s
    end
  end
end
