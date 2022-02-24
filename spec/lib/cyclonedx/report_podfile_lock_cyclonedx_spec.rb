require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportPodfileLock do
  describe "#run" do
    it 'should report all the deps in the Podfile.lock' do
      repo = Salus::Repo.new('spec/fixtures/report_podfile_lock/normal')
      scanner = Salus::Scanners::ReportPodfileLock.new(repository: repo, config: {})
      scanner.run

      cocoa_cyclonedx = Cyclonedx::ReportPodfileLock.new(scanner.report)

      expect(cocoa_cyclonedx.build_components_object).to match_array(
        [
          {
            type: "library",
          "group": "",
            name: "boost-for-react-native",
            version: '1.63.0',
            purl: "pkg:cocoapods/boost-for-react-native@1.63.0"
          },
          {
            type: "library",
          "group": "",
            name: "CocoaAsyncSocket",
            version: '7.6.5',
            purl: "pkg:cocoapods/CocoaAsyncSocket@7.6.5"
          },
          {
            type: "library",
          "group": "",
            name: "Flipper",
            version: "0.87.0",
            purl: "pkg:cocoapods/Flipper@0.87.0"
          }
        ]
      )
    end

    it 'should produce valid CycloneDX under normal conditions' do
      repo = Salus::Repo.new('spec/fixtures/report_podfile_lock/normal')

      scanner = Salus::Scanners::ReportPodfileLock.new(repository: repo, config: {})
      scanner.run

      cyclonedx_report = Cyclonedx::Report.new([[scanner.report, false]],
                                               { "spec_version" => "1.3" })
      cyclonedx_report_hash = cyclonedx_report.to_cyclonedx

      expect { Cyclonedx::Report.validate_cyclonedx(cyclonedx_report_hash) }.not_to raise_error
    end

    it 'should produce valid CycloneDX when an unparseable file is found' do
      repo = Salus::Repo.new('spec/fixtures/report_podfile_lock/bad_podfile_cant_parse')

      scanner = Salus::Scanners::ReportPodfileLock.new(repository: repo, config: {})
      scanner.run

      cyclonedx_report = Cyclonedx::Report.new([[scanner.report, false]],
                                               { "spec_version" => "1.3" })
      cyclonedx_report_hash = cyclonedx_report.to_cyclonedx

      expect { Cyclonedx::Report.validate_cyclonedx(cyclonedx_report_hash) }.not_to raise_error
    end
  end
end
