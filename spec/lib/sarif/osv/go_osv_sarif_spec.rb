require_relative '../../../spec_helper'
require 'json'

describe Sarif::GoOSVSarif do
  let(:osv) { "../../../../spec/fixtures/osv/go_osv/" }
  let(:file) { File.expand_path(osv, __dir__) }
  let(:config_file) { YAML.load_file("#{file}/failure_vulnerability_present/salus.yaml") }
  let(:scanner_config) { config_file['scanner_configs']["GoOSV"] }

  def stub_req_with_valid_response
    stub_request(:get, "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip")
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

  context 'with vulnerable go project' do
    let(:repo) { Salus::Repo.new('spec/fixtures/osv/go_osv/failure_vulnerability_present') }
    it 'should generate report with logged vulnerabilities' do
      scanner = Salus::Scanners::OSV::GoOSV.new(repository: repo, config: {})
      stub_req_with_valid_response
      scanner.run
      report = Salus::Report.new(project_name: "Neon Genesis")
      report.add_scan_report(scanner.report, required: false)
      sarif = JSON.parse(report.to_sarif)

      expect(sarif['runs'][0]['tool']['driver']['rules'][0]).to include(
        { "fullDescription" =>
          { "text" => "Due to improper HTTP header santization, a malicious user can spoof their" },
        "help" => {
          "markdown" => "[More info]"\
          "(https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0052.yaml).",
            "text" => "More info: https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0052.yaml"

        },
        "helpUri" =>
        "https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0052.yaml",
        "id" => "CVE-2020-28483", "messageStrings" =>
        { "package" => { "text" => "github.com/gin-gonic/gin" },
        "patched_versions" => { "text" => "1.6.3-0.20210406033725-bfc8ca285eb4" },
        "severity" => { "text" => "LOW" },
        "title" => { "text" =>
          "Due to improper HTTP header santization, a malicious user can spoof their" },
        "vulnerable_versions" => { "text" => "0" } }, "name" => "GoOSV" }
      )

      expect(sarif['runs'][0]['results']).to include(
        { "level" => "warning",
          "locations" => [
            { "physicalLocation" =>
              { "artifactLocation" =>
                 { "uri" => "https://osv.dev/list", "uriBaseId" => "%SRCROOT%" } } }
          ],
            "message" => { "text" =>
              "Due to improper HTTP header santization, a malicious user can spoof their" },
            "properties" => { "severity" => "LOW" },
            "ruleId" => "CVE-2020-28483",
            "ruleIndex" => 0,
            "suppressions" => [{ "kind" => "external" }] }
      )
    end
  end

  context 'with vulnerable go project but exceptions configured' do
    let(:repo) { Salus::Repo.new('spec/fixtures/osv/go_osv/failure_vulnerability_present') }

    it 'should generate an empty sarif report' do
      scanner = Salus::Scanners::OSV::GoOSV.new(repository: repo,
        config: scanner_config)
      stub_req_with_valid_response
      scanner.run
      report = Salus::Report.new(project_name: "Neon Genesis")
      report.add_scan_report(scanner.report, required: false)
      report_object = JSON.parse(report.to_sarif)['runs'][0]

      expect(report_object['results'].length).to eq(0)
      expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
    end
  end

  context 'with non vulnerable go project' do
    let(:repo) { Salus::Repo.new('spec/fixtures/osv/go_osv/success_no_vulnerability') }
    it 'should generate an empty sarif report' do
      scanner = Salus::Scanners::OSV::GoOSV.new(repository: repo, config: {})
      stub_req_with_valid_response
      scanner.run
      report = Salus::Report.new(project_name: "Neon Genesis")
      report.add_scan_report(scanner.report, required: false)
      report_object = JSON.parse(report.to_sarif)['runs'][0]

      expect(report_object['results'].length).to eq(0)
      expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
    end
  end
end
