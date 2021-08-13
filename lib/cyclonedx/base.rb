module Cyclonedx
  class Base
    DEFAULT_DEP_COMPONENT_TYPE = "library".freeze
    class CycloneDXInvalidVersionError < StandardError; end

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
      component = build_component(dependency)
      component[:properties] = build_properties(dependency)

      # Default to version 1.3 if no spec version is specified
      return component unless @config['spec_version'].present?

      case @config['spec_version']
      when "1.2"
        component.delete(:properties)
        component
      when "1.3"
        component
      else
        raise CycloneDXInvalidVersionError,
              "Incorrect Cyclone Version Specified: #{@config['spec_version']}." \
              " Should be exactly 1.2 or 1.3"
      end
    end

    def build_component(dependency)
      {
        "bom-ref": package_url(dependency),
        "type": DEFAULT_DEP_COMPONENT_TYPE,
        "group": "", # TODO: add group or domain name of the publisher
        "name": dependency[:name],
        "version": version_string(dependency),
        "purl": package_url(dependency),
      }
    end

    def build_properties(dependency)
      [
        {
          "key": "source",
          # Varies between these two values by scanner
          "value": dependency[:source] || dependency[:reference].to_s
        },
        {
          "key": "dependency_file",
          "value": dependency[:dependency_file]
        }
      ]
    end
  end
end
