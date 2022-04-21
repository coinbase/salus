require_relative '../../../spec_helper'
require 'json'

describe Sarif::GoPackageScannerSarif do
  let(:path) { 'spec/fixtures/package_version/go_package_version_scanner/' }
  let(:config_file) { YAML.load_file("#{path}/salus_fail_with_range.yml") }
  let(:scanner_config) { config_file['scanner_configs']["GoPackageScanner"] }

  context 'go package version mismatch' do
    let(:repo) { Salus::Repo.new('spec/fixtures/osv/go_osv/failure_vulnerability_present') }
    it 'should generate error in report' do
      scanner = Salus::Scanners::PackageVersion::GoPackageScanner.new(repository: repo,
      config: scanner_config)
      url = "https://github.com/coinbase/salus/blob/master/docs/scanners/package_version_scan.md"
      scanner.run
      report = Salus::Report.new(project_name: "Neon Genesis")
      report.add_scan_report(scanner.report, required: false)
      sarif = JSON.parse(report.to_sarif({ 'include_non_enforced' => true }))

      # contains rule
      expect(sarif['runs'][0]['tool']['driver']['rules'][0]).to include(
        { "id" => "PV0001",
         "name" => "GoPackageScanner",
         "fullDescription" => {
           "text" => "Package version does not fall within specified range"
         }, "messageStrings" => {}, "helpUri" => url,
         "help" => { "text" => "More info: #{url}",
         "markdown" => "[More info](#{url})." } }
      )

      # contains version mismatch
      expect(sarif['runs'][0]['results']).to include(
        { "ruleId" => "PV0001",
         "ruleIndex" => 0, "level" => "error",
         "message" => { "text" => "Package version for (github.com/syncthing/syncthing) (1.14.0)"\
            " is greater than maximum configured version (1.0.5) in go.sum." },
         "locations" => [{ "physicalLocation" => {
           "artifactLocation" => { "uri" => "go.sum",
         "uriBaseId" => "%SRCROOT%" }
         } }],
           "properties" => { "severity" => "HIGH" } }
      )
    end
  end
end
