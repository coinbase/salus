require_relative '../../../spec_helper'
require 'json'

describe Sarif::GradleOSVSarif do
  let(:osv) { "../../../../spec/fixtures/osv/gradle_osv/" }
  let(:file) { File.expand_path(osv, __dir__) }
  let(:config_file) do
    YAML.load_file("#{file}/success_vulnerability_present_exception_added/salus.yaml")
  end
  let(:scanner_config) { config_file['scanner_configs']["GradleOSV"] }

  def stub_req_with_valid_response
    stub_request(:get, "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip")
      .with(
        headers: {
          'Accept' => '*/*',
          'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
          'Host' => 'osv-vulnerabilities.storage.googleapis.com',
          'User-Agent' => 'Ruby'
        }
      )
      .to_return(
        status: 200,
        body: File.read(File.join(file, 'all.zip')),
        headers: {}
      )
  end

  context 'with vulnerable gradle project' do
    let(:repo) { Salus::Repo.new('spec/fixtures/osv/gradle_osv/failure_vulnerability_present') }
    it 'should generate report with logged vulnerabilities' do
      scanner = Salus::Scanners::OSV::GradleOSV.new(repository: repo, config: {})
      stub_req_with_valid_response
      scanner.run
      report = Salus::Report.new(project_name: "Neon Genesis")
      report.add_scan_report(scanner.report, required: false)
      sarif = JSON.parse(report.to_sarif({ 'include_non_enforced' => true }))

      expect(sarif['runs'][0]['tool']['driver']['rules'][0]).to include(
        {
          "fullDescription" => {
            "text" => "Information Disclosure in Guava"
          },
            "help" => {
              "markdown" => "[More info](https://osv.dev/list).",
              "text" => "More info: https://osv.dev/list"
            },
            "helpUri" => "https://osv.dev/list",
            "id" => "CVE-2020-8908",
            "messageStrings" => {
              "package" => {
                "text" => "com.google.guava:guava"
              },
              "patched_versions" => {
                "text" => ""
              },
              "severity" => {
                "text" => "LOW"
              },
              "title" => {
                "text" => "Information Disclosure in Guava"
              },
              "vulnerable_versions" => {
                "text" => "0"
              }
            },
            "name" => "GradleOSV"
        }
      )

      expect(sarif['runs'][0]['results'][0]).to include(
        {
          "level" => "warning",
            "locations" => [
              {
                "physicalLocation" => {
                  "artifactLocation" => {
                    "uri" => "https://osv.dev/list",
                    "uriBaseId" => "%SRCROOT%"
                  }
                }
              }
            ],
            "message" => {
              "text" => "Information Disclosure in Guava"
            },
            "properties" => {
              "severity" =>  "LOW"
            },
            "ruleId" => "CVE-2020-8908",
            "ruleIndex" => 0
        }
      )

      filtered_sarif = report.apply_report_sarif_filters(sarif)
      expect { Sarif::SarifReport.validate_sarif(filtered_sarif) }.not_to raise_error
    end
  end

  context 'with vulnerable gradle project but exceptions configured' do
    let(:repo) do
      Salus::Repo.new(
        'spec/fixtures/osv/gradle_osv/success_vulnerability_present_exception_added'
      )
    end

    it 'should generate an empty sarif report' do
      scanner = Salus::Scanners::OSV::GradleOSV.new(repository: repo,
        config: scanner_config)
      stub_req_with_valid_response
      scanner.run
      report = Salus::Report.new(project_name: "Neon Genesis")
      report.add_scan_report(scanner.report, required: false)
      report_object = JSON.parse(report.to_sarif)

      expect(report_object['runs'][0]['results'].length).to eq(0)
      expect(report_object['runs'][0]['invocations'][0]['executionSuccessful']).to eq(true)

      filtered_sarif = report.apply_report_sarif_filters(report_object)
      expect { Sarif::SarifReport.validate_sarif(filtered_sarif) }.not_to raise_error
    end
  end

  context 'with non vulnerable gradle project' do
    let(:repo) { Salus::Repo.new('spec/fixtures/osv/gradle_osv/success_no_vulnerability') }
    it 'should generate an empty sarif report' do
      scanner = Salus::Scanners::OSV::GradleOSV.new(repository: repo, config: {})
      stub_req_with_valid_response
      scanner.run
      report = Salus::Report.new(project_name: "Neon Genesis")
      report.add_scan_report(scanner.report, required: false)
      report_object = JSON.parse(report.to_sarif)

      expect(report_object['runs'][0]['results'].length).to eq(0)
      expect(report_object['runs'][0]['invocations'][0]['executionSuccessful']).to eq(true)

      filtered_sarif = report.apply_report_sarif_filters(report_object)
      expect { Sarif::SarifReport.validate_sarif(filtered_sarif) }.not_to raise_error
    end
  end
end
