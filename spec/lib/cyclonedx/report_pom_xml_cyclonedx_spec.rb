require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportPomXml do
  describe "#run" do
    it 'should report all the deps in the pom.xml' do
      repo = Salus::Repo.new('spec/fixtures/report_pom_xml/normal')
      scanner = Salus::Scanners::ReportPomXml.new(repository: repo, config: {})
      scanner.run

      maven_cyclonedx = Cyclonedx::ReportPomXml.new(scanner.report)
      expect(maven_cyclonedx.build_components_object).to match_array(
        [
          {
            type: "library",
          "group": "",
            name: "org.apache.kafka/connect-api",
            version: Salus::Scanners::ReportPomXml::UNKNOWN_VERSION.to_s,
            purl: "pkg:maven/org.apache.kafka/connect-api"
          },
          {
            type: "library",
          "group": "",
            name: "org.apache.kafka/connect-json",
            version: Salus::Scanners::ReportPomXml::UNKNOWN_VERSION.to_s,
            purl: "pkg:maven/org.apache.kafka/connect-json"
          },
          {
            type: "library",
          "group": "",
            name: "junit/junit",
            version: "1.1.1",
            purl: "pkg:maven/junit/junit"
          }
        ]
      )
    end

    it 'should produce valid CycloneDX under normal conditions' do
      repo = Salus::Repo.new('spec/fixtures/report_pom_xml/normal')

      scanner = Salus::Scanners::ReportPomXml.new(repository: repo, config: {})
      scanner.run

      cyclonedx_report = Cyclonedx::Report.new([[scanner.report, false]],
                                               { "spec_version" => "1.3" })
      cyclonedx_report_hash = cyclonedx_report.to_cyclonedx

      expect { Cyclonedx::Report.validate_cyclonedx(cyclonedx_report_hash) }.not_to raise_error
    end
  end
end
