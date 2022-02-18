require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportGradleDeps do
  describe "#run" do
    it 'should report all the deps in the build.gradle' do
      repo = Salus::Repo.new('spec/fixtures/report_gradle_deps/normal')
      scanner = Salus::Scanners::ReportGradleDeps.new(repository: repo, config: {})
      scanner.run

      gradle_cyclonedx = Cyclonedx::ReportGradleDeps.new(scanner.report)
      components_object = gradle_cyclonedx.build_components_object
      expect(components_object.size).to eq(61)
      expect(components_object).to include(
        {
          type: "library",
          "group": "",
          name: "org.apache.kafka/connect-transforms",
          version: "2.6.2",
          purl: "pkg:gradle/org.apache.kafka/connect-transforms"
        },
        {
          type: "library",
          "group": "",
          name: "org.apache.kafka/connect-api",
          version: "2.6.2",
          purl: "pkg:gradle/org.apache.kafka/connect-api"
        },
        {
          type: "library",
          "group": "",
          name: "org.apache.kafka/kafka-clients",
          version: "2.6.2",
          purl: "pkg:gradle/org.apache.kafka/kafka-clients"
        }
      )
    end

    it 'should produce valid CycloneDX under normal conditions' do
      repo = Salus::Repo.new('spec/fixtures/report_gradle_deps/normal')

      scanner = Salus::Scanners::ReportGradleDeps.new(repository: repo, config: {})
      scanner.run

      cyclonedx_report = Cyclonedx::Report.new([[scanner.report, false]],
                                               { "spec_version" => "1.3" })
      cyclonedx_report_hash = cyclonedx_report.to_cyclonedx

      expect { Cyclonedx::Report.validate_cyclonedx(cyclonedx_report_hash) }.not_to raise_error
    end
  end
end
