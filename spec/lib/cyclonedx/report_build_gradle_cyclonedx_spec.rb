require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportBuildGradle do
  describe "#run" do
    it 'should report all the deps in the build.gradle' do
      repo = Salus::Repo.new('spec/fixtures/report_build_gradle/normal')
      scanner = Salus::Scanners::ReportBuildGradle.new(repository: repo, config: {})
      scanner.run

      gradle_cyclonedx = Cyclonedx::ReportBuildGradle.new(scanner.report)
      expect(gradle_cyclonedx.build_components_object).to match_array(
        [
          {
            "bom-ref": "pkg:gradle/com.android.tools.build/gradle",
            type: "library",
            group: "",
            name: "com.android.tools.build/gradle",
            version: '3.5.3',
            purl: "pkg:gradle/com.android.tools.build/gradle",
            properties: [
              { key: "source", value: "" },
              { key: "dependency_file", value: "build.gradle" }
            ]
          },
          {
            "bom-ref": "pkg:gradle/com.facebook.react/react-native",
            type: "library",
            group: "",
            name: "com.facebook.react/react-native",
            version: '+',
            purl: "pkg:gradle/com.facebook.react/react-native",
            properties: [
              { key: "source", value: "" },
              { key: "dependency_file", value: "build.gradle" }
            ]
          },
          {
            "bom-ref": "pkg:gradle/androidx.work/work-runtime",
            type: "library",
            group: "",
            name: "androidx.work/work-runtime",
            version: "2.4.0",
            purl: "pkg:gradle/androidx.work/work-runtime",
            properties: [
              { key: "source", value: "" },
              { key: "dependency_file", value: "build.gradle" }
            ]
          },
          {
            "bom-ref": "pkg:gradle/androidx.security/security-crypto",
            type: "library",
            group: "",
            name: "androidx.security/security-crypto",
            version: "1.0.0",
            purl: "pkg:gradle/androidx.security/security-crypto",
            properties: [
              { key: "source", value: "" },
              { key: "dependency_file", value: "build.gradle" }
            ]
          },
          {
            "bom-ref": "pkg:gradle/com.google.code.gson/gson",
            type: "library",
            group: "",
            name: "com.google.code.gson/gson",
            version: "2.8.8",
            purl: "pkg:gradle/com.google.code.gson/gson",
            properties: [
              { key: "source", value: "" },
              { key: "dependency_file", value: "build.gradle" }
            ]
          }
        ]
      )
    end

    it 'should produce valid CycloneDX under normal conditions' do
      repo = Salus::Repo.new('spec/fixtures/report_build_gradle/normal')

      scanner = Salus::Scanners::ReportBuildGradle.new(repository: repo, config: {})
      scanner.run

      cyclonedx_report = Cyclonedx::Report.new([[scanner.report, false]],
                                               { "spec_version" => "1.3" })
      cyclonedx_report_hash = cyclonedx_report.to_cyclonedx

      expect { Cyclonedx::Report.validate_cyclonedx(cyclonedx_report_hash) }.not_to raise_error
    end
  end
end
