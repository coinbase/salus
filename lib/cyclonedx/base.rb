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
      @scan_report.info[:dependencies].each do |dependency|
        component = {
          "bom-ref": "",
          "type": DEFAULT_COMPONENT_TYPE,
          "group": "",
          "name": dependency[:name],
          "version": "",
          "purl": ""
        }

        # TODO: Add specific component parsing for individual scanners
        components << component
      end
      components
    end
  end
end
