module Cyclonedx
  class Base
    DEFAULT_COMPONENT_TYPE = "application".freeze

    def initialize(scan_report, config = {})
      @scan_report = scan_report
      @config = config
    end

    def build_metadata
      {
        "timestamp": "",
        "component": {
          "bom-ref": "",
          "type": DEFAULT_COMPONENT_TYPE,
          "group": "",
          "name": "",
          "version": "",
          "purl": ""
        }
      }
    end

    # Returns the 'components' object for a supported/unsupported scanner's report
    def build_components_object
      components = []
      info = @scan_report.to_h.fetch(:info)
      info[:dependencies].each do |dependency|
        components << parse_dependency(dependency)
      end
      components
    end
  end
end
