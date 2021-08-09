module Cyclonedx
  class Base
    DEFAULT_DEP_COMPONENT_TYPE = "library".freeze

    attr_accessor :config

    def initialize(scan_report, config = {})
      @scan_report = scan_report
      @config = config
    end

    # Returns the 'components' object for a supported/unsupported scanner's report
    def build_components_object
      info = @scan_report.to_h.fetch(:info)
      return [] unless info[:dependencies]

      components = []

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
        "version": version_string(dependency),
        "purl": package_url(dependency),
        "properties": [
          {
            "key": "source",
            # Varies between these two values by scanner
            "value": dependency[:source] || dependency[:reference]
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
