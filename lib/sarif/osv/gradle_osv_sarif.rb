require 'sarif/osv/base_sarif'

module Sarif
  class GradleOSVSarif < Sarif::OSV::BaseSarif
    def parse_issue(issue)
      super.merge(
        {
          name: "GradleOSV"
        }
      )
    end
  end
end
