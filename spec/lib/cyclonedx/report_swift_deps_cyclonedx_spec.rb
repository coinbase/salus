require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportSwiftDeps do
  describe "#run" do
    it 'should report all the deps in the Package.resolved' do
      repo = Salus::Repo.new('spec/fixtures/report_swift_deps/normal')
      scanner = Salus::Scanners::ReportSwiftDeps.new(repository: repo, config: {})
      scanner.run

      swift_cyclonedx = Cyclonedx::ReportSwiftDeps.new(scanner.report)
      expect(swift_cyclonedx.build_components_object).to match_array(
        [
          {
            type: "library",
          "group": "",
              name: "Cryptor",
              version: "2.0.1",
              purl: "pkg:swift/Cryptor"
          },
          {
            type: "library",
          "group": "",
              name: "CryptorECC",
              version: "1.2.200",
              purl: "pkg:swift/CryptorECC"
          },
          {
            type: "library",
          "group": "",
              name: "CryptorRSA",
              version: "1.0.201",
              purl: "pkg:swift/CryptorRSA"
          }
        ]
      )
    end

    it 'should produce valid CycloneDX under normal conditions' do
      repo = Salus::Repo.new('spec/fixtures/report_swift_deps/normal')

      scanner = Salus::Scanners::ReportSwiftDeps.new(repository: repo, config: {})
      scanner.run

      cyclonedx_report = Cyclonedx::Report.new([[scanner.report, false]],
                                               { "spec_version" => "1.3" })
      cyclonedx_report_hash = cyclonedx_report.to_cyclonedx

      expect { Cyclonedx::Report.validate_cyclonedx(cyclonedx_report_hash) }.not_to raise_error
    end

    it 'should produce valid CycloneDX when an unparseable file is found' do
      repo = Salus::Repo.new('spec/fixtures/report_swift_deps/bad_file_cant_parse')

      scanner = Salus::Scanners::ReportSwiftDeps.new(repository: repo, config: {})
      scanner.run

      cyclonedx_report = Cyclonedx::Report.new([[scanner.report, false]],
                                               { "spec_version" => "1.3" })
      cyclonedx_report_hash = cyclonedx_report.to_cyclonedx

      expect { Cyclonedx::Report.validate_cyclonedx(cyclonedx_report_hash) }.not_to raise_error
    end
  end
end
