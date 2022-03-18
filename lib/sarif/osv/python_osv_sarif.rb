require 'sarif/osv/base_sarif'

module Sarif
  class PythonOSVSarif < Sarif::OSV::BaseSarif
    def parse_issue(issue)
      super.merge(
        {
          name: "PythonOSV"
        }
      )
    end
  end
end
