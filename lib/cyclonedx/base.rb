module Cyclonedx
  class Base
    DEFAULT_COMPONENT_TYPE = "application".freeze
    DEFAULT_DEP_COMPONENT_TYPE = "library".freeze

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

    def parse_dependency(dependency)
      {
        "bom-ref": package_url(dependency),
        "type": DEFAULT_DEP_COMPONENT_TYPE,
        "group": "", # TODO: add group or domain name of the publisher
        "name": dependency[:name],
        "version": dependency[:version],
        "purl": package_url(dependency),
        "properties": [
          {
            "key": "source",
            "value": dependency[:source]
          },
          {
            "key": "dependency_file",
            "value": dependency[:dependency_file]
          }
        ]
      }
    end
  end
end
