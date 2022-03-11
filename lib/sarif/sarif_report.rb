require 'json'
require 'json-schema'
require_relative './base_sarif'

paths = ['./', 'language_version', 'package_version', 'osv']
paths.each do |path|
  Dir.entries(File.expand_path(path, __dir__)).sort.each do |filename|
    next unless /_sarif.rb\z/.match?(filename) && !filename.eql?('base_sarif.rb')

    require_relative "#{path}/#{filename}"
  end
end
module Sarif
  # Class for generating sarif reports
  class SarifReport
    class SarifInvalidFormatError < StandardError; end

    SARIF_VERSION = "2.1.0".freeze

    SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v#{SARIF_VERSION}/csprd01/schemas/"\
    "sarif-schema-#{SARIF_VERSION}".freeze

    def initialize(scan_reports, config = {}, repo_path = nil)
      @scan_reports = scan_reports
      @config = config
      @repo_path = repo_path
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
      @scan_reports.each do |scan_report|
        # scan_report[0] Salus::ScanReport scan report
        # scan_report[1] boolean required (enforced scanner)
        sarif_report["runs"] << converter(scan_report[0], scan_report[1])
      end
      report = JSON.pretty_generate(sarif_report)
      Sarif::SarifReport.validate_sarif(report)
    end

    def self.validate_sarif(sarif_string)
      path = File.expand_path('schema/sarif-schema.json', __dir__)
      schema = JSON.parse(File.read(path))

      return sarif_string if JSON::Validator.validate(schema, sarif_string)

      errors = JSON::Validator.fully_validate(schema, sarif_string)
      raise SarifInvalidFormatError, "Incorrect Sarif Output: #{errors}"
    end

    # Converts a ScanReport to a sarif report for the given scanner
    #
    # @params sarif_report [Salus::ScanReport]
    # @return
    def converter(scan_report, required)
      adapter = "Sarif::#{scan_report.scanner_name}Sarif"
      begin
        converter = Object.const_get(adapter).new(scan_report, @repo_path)
        converter.config = @config
        converter.required = required
        converter.build_runs_object(true)
      rescue NameError # this is greedy and will catch NoMethodError's too
        converter = BaseSarif.new(scan_report, @config, @repo_path)
        converter.required = required
        converter.build_runs_object(false)
      end
    end
  end
end
