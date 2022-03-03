require 'sarif/osv/base_sarif'

module Sarif
  class MavenOSVSarif < Sarif::OSV::BaseSarif
    def parse_issue(issue)
      super.merge(
        {
          name: "MavenOSV"
        }
      )
    end
  end
end
