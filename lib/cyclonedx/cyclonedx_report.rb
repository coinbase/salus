require 'securerandom'

Dir.entries(File.expand_path('./', __dir__)).sort.each do |filename|
  next unless /_cyclonedx.rb\z/.match?(filename) && !filename.eql?('base_cyclonedx.rb')

  require_relative filename
end

module Cyclonedx
  class CyclonedxReport
    def initialize(scan_reports, config = {})
      @scan_reports = scan_reports
      @config = config
    end

    CYCLONEDX_SPEC_VERSION = "1.2.0".freeze
    CYCLONEDX_VERSION = "1".freeze
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
      cyclonedx_report[:metadata] = converter.build_metadata

      # for each scanner report, run the appropriate converter
      @scan_reports.each do |scan_report|
        cyclonedx_report[:components] << converter(scan_report[0])
      end
      JSON.pretty_generate(cyclonedx_report)
    end

    # Converts a ScanReport to a cyclonedx report for the given scanner
    def converter(scan_report)
      adapter = "Cyclonedx::#{scan_report.scanner_name}Cyclonedx"
      begin
        converter = Object.const_get(adapter).new(scan_report)
        converter.config = @config
      rescue NameError
        converter = BaseCyclonedx.new(scan_report, @config)
      end
      converter.build_components_object
    end

    def random_urn_uuid
      "urn:uuid:#{SecureRandom.uuid}"
    end
  end
end
