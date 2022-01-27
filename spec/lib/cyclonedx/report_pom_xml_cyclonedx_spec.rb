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
            "bom-ref": "pkg:maven/org.apache.kafka/connect-api",
            type: "library",
            group: "",
            name: "org.apache.kafka/connect-api",
            version: "unknown",
            purl: "pkg:maven/org.apache.kafka/connect-api",
            properties: [
              { key: "source", value: "" },
              { key: "dependency_file", value: "pom.xml" }
            ]
          },
          {
            "bom-ref": "pkg:maven/org.apache.kafka/connect-json",
            type: "library",
            group: "",
            name: "org.apache.kafka/connect-json",
            version: "unknown",
            purl: "pkg:maven/org.apache.kafka/connect-json",
            properties: [
              { key: "source", value: "" },
              { key: "dependency_file", value: "pom.xml" }
            ]
          },
          {
            "bom-ref": "pkg:maven/junit/junit",
            type: "library",
            group: "",
            name: "junit/junit",
            version: "1.1.1",
            purl: "pkg:maven/junit/junit",
            properties: [
              { key: "source", value: "" },
              { key: "dependency_file", value: "pom.xml" }
            ]
          }
        ]
      )
    end
  end
end
