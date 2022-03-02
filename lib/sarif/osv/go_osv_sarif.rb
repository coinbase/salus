require 'sarif/osv/base_sarif'

module Sarif
  class GoOSVSarif < Sarif::OSV::BaseSarif
    def parse_issue(issue)
      super.merge(
        {
          name: "GoOSV"
        }
      )
    end
  end
end
