require 'salus/scanners/base'

# Report Java library usage

module Salus::Scanners
  class ReportPomXml < Base
    def self.scanner_type
      Salus::ScannerTypes::SBOM_REPORT
    end

    UNKNOWN_VERSION = ''.freeze

    def run
      begin
        parser = Salus::MavenDependencyParser.new(@repository.pom_xml_path)
        parser.parse
      rescue StandardError => e
        report_stderr(e.message)
        report_error(e.message)
        return
      end

      parser.pom_xml_dependencies.each do |dependency|
        group_id = dependency['group_id']
        artifact_id = dependency['artifact_id']
        report_error('No group ID found for a dependency!') if group_id.nil?
        report_error('No artifact ID found for a dependency!') if artifact_id.nil?
        report_dependency(
          'pom.xml',
          type: 'maven',
          name: artifact_id.nil? ? group_id : "#{group_id}/#{artifact_id}",
          version: dependency['version'].nil? ? UNKNOWN_VERSION : dependency['version']
        )
      end
    end

    def should_run?
      @repository.pom_xml_present?
    end

    def self.supported_languages
      ['java']
    end
  end
end
