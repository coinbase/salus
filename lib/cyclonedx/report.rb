require 'securerandom'
require 'json'
require 'json-schema'
require_relative './base'
require_relative './package_url'
require 'salus/bugsnag'

Dir.entries(File.expand_path('./', __dir__)).sort.each do |filename|
  next unless /_cyclonedx.rb\z/.match?(filename) && !filename.eql?('base_cyclonedx.rb')

  require_relative filename
end

module Cyclonedx
  class Report
    include Salus::SalusBugsnag

    DEFAULT_COMPONENT_TYPE = "application".freeze
    class CycloneDXInvalidFormatError < StandardError; end
    class CycloneDXInvalidVersionError < StandardError; end

    def initialize(scan_reports, config = {})
      @scan_reports = scan_reports
      @config = config
    end

    CYCLONEDX_DEFAULT_SPEC_VERSION = "1.3".freeze
    CYCLONEDX_VERSION = 1
    CYCLONEDX_FORMAT = "CycloneDX".freeze
    VALID_SPEC_VERSIONS = %w[1.3 1.2].freeze

    # Build CycloneDX Report.
    def to_cyclonedx
      unless is_valid_spec_version
        raise CycloneDXInvalidVersionError, "Incorrect Cyclone version #{spec_version} " \
        "Should be exactly 1.2 or 1.3"
      end

      cyclonedx_report = {
        bomFormat: CYCLONEDX_FORMAT,
        specVersion: spec_version,
        serialNumber: random_urn_uuid,
        version: CYCLONEDX_VERSION,
        metadata: {},
        components: []
      }

      # for each scanner report, run the appropriate converter
      @scan_reports.each do |scan_report|
        cyclonedx_report[:components] += converter(scan_report[0])
      rescue StandardError => e
        msg = "CycloneDX reporting errored on #{scan_report[0].scanner_name} " \
              "with error message #{e.class}: #{e.message}"
        bugsnag_notify(msg)
      end

      cyclonedx_report[:components].uniq!
      Cyclonedx::Report.validate_cyclonedx(cyclonedx_report)
    end

    def self.validate_cyclonedx(cyclonedx_report)
      cyclonedx_string = JSON.pretty_generate(cyclonedx_report)
      path = File.expand_path("schema/bom-#{cyclonedx_report[:specVersion]}.schema.json", __dir__)
      schema = JSON.parse(File.read(path))
      return cyclonedx_report if JSON::Validator.validate(schema, cyclonedx_string)

      errors = JSON::Validator.fully_validate(schema, cyclonedx_string)
      raise CycloneDXInvalidFormatError, "Incorrect Cyclone Output: #{errors}"
    end

    # Converts a ScanReport to a cyclonedx report for the given scanner
    def converter(scan_report)
      adapter = "Cyclonedx::#{scan_report.scanner_name}"
      begin
        converter = Object.const_get(adapter).new(scan_report)
        converter.config = @config
      rescue NameError
        converter = Cyclonedx::Base.new(scan_report, @config)
      end
      converter.build_components_object
    end

    def random_urn_uuid
      "urn:uuid:#{SecureRandom.uuid}"
    end

    def spec_version
      @config['spec_version'] || CYCLONEDX_DEFAULT_SPEC_VERSION
    end

    def is_valid_spec_version
      VALID_SPEC_VERSIONS.include?(spec_version)
    end
  end
end
