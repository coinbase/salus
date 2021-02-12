require 'json'
require 'json-schema'
require_relative './base_sarif'
require_relative './gosec_sarif'

module Sarif
  # Class for generating sarif reports
  class SarifReport
    class SarifInvalidFormatError < StandardError; end

    SARIF_VERSION = "2.1.0".freeze

    SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas"\
      "/json/sarif-2.1.0-rtm.5.json".freeze

    def initialize(scan_reports)
      @scan_reports = scan_reports
    end

    # Builds Sarif Report. Raises an SarifInvalidFormatError if generated SARIF report is invalid
    #
    # @return [JSON]
    def to_sarif
      sarif_report = {
        "version" => SARIF_VERSION,
        "$schema" => SARIF_SCHEMA,
        "runs" => []
      }
      # for each scanner report, run the appropriate converter
      @scan_reports.each { |scan_report| sarif_report["runs"] << converter(scan_report[0]) }
      report = JSON.pretty_generate(sarif_report)
      path = File.expand_path('schema/sarif-schema.json', __dir__)
      schema = JSON.parse(File.read(path))

      if JSON::Validator.validate(schema, report)
        report
      else
        errors = JSON::Validator.fully_validate(schema, report)
        raise SarifInvalidFormatError, "Incorrect Sarif Output: #{errors}" end
    end

    # Converts a ScanReport to a sarif report for the given scanner
    #
    # @params sarif_report [Salus::ScanReport]
    # @return
    def converter(scan_report)
      adapter = "Sarif::#{scan_report.scanner_name}Sarif"
      begin
        converter = Object.const_get(adapter).new(scan_report)
      rescue NameError
        converter = BaseSarif.new(scan_report)
        return converter.build_runs_object
      end
      converter.build_runs_object
    end
  end
end
