module Cyclonedx
  class Base
    DEFAULT_DEP_COMPONENT_TYPE = "library".freeze
    TYPE = "N/A".freeze
    UNLOCKED_DEPENDENCY_FILE = "N/A".freeze

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
        "purl": package_url(dependency)
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

    def package_url(dependency)
      PackageUrl.new(type: self.class::TYPE,
                     namespace: dependency[:name],
                     version: version_string(dependency, true)).to_string
    end

    # Return version string to be used in purl or component
    def version_string(dependency, is_purl_version = false)
      # If the dependency is specified in a unlocked dependency file and an absolute version
      # is needed for the purl return empty
      if dependency[:dependency_file] == self.class::UNLOCKED_DEPENDENCY_FILE && is_purl_version
        return ""
      end

      dependency[:version]
    end
  end
end
