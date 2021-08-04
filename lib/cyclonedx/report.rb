require 'securerandom'
require 'json'
require 'json-schema'
require_relative './base'

Dir.entries(File.expand_path('./', __dir__)).sort.each do |filename|
  next unless /_cyclonedx.rb\z/.match?(filename) && !filename.eql?('base_cyclonedx.rb')

  require_relative filename
end

module Cyclonedx
  class Report
    DEFAULT_COMPONENT_TYPE = "application".freeze
    class CycloneDXInvalidFormatError < StandardError; end

    def initialize(scan_reports, config = {})
      @scan_reports = scan_reports
      @config = config
    end

    CYCLONEDX_SPEC_VERSION = "1.3".freeze
    CYCLONEDX_VERSION = 1.freeze
    CYCLONEDX_FORMAT = "CycloneDX".freeze

    # Build CycloneDX Report.
    def to_cyclonedx
      cyclonedx_report = {
        bomFormat: CYCLONEDX_FORMAT,
        specVersion: CYCLONEDX_SPEC_VERSION,
        serialNumber: random_urn_uuid,
        version: CYCLONEDX_VERSION,
        metadata: {},
        components: []
      }

      # for each scanner report, run the appropriate converter
      @scan_reports.each do |scan_report|
        cyclonedx_report[:components] += converter(scan_report[0])
      end
      report = JSON.pretty_generate(cyclonedx_report)
      Cyclonedx::Report.validate_cyclonedx(report)
    end

    def self.validate_cyclonedx(cyclonedx_string)
      path = File.expand_path('schema/bom-1.3.schema.json', __dir__)
      schema = JSON.parse(File.read(path))
      return cyclonedx_string if JSON::Validator.validate(schema, cyclonedx_string)

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
  end
end
