require_relative '../../../spec_helper'
require 'json'

describe Sarif::NPMPackageScannerSarif do
  let(:path) { 'spec/fixtures/package_version/npm_package_version_scanner/' }
  let(:config_file) { YAML.load_file("#{path}/salus.yml") }
  let(:config_file2) { YAML.load_file("#{path}/salus2.yml") }
  let(:scanner_config) { config_file['scanner_configs']["NPMPackageScanner"] }
  let(:scanner_config2) { config_file2['scanner_configs']["NPMPackageScanner"] }

  context 'npm package version mismatch' do
    let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/failure') }
    it 'should generate error in report' do
      scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
      config: scanner_config)
      url = "https://github.com/coinbase/salus/blob/master/docs/scanners/package_version_scan.md"
      scanner.run
      report = Salus::Report.new(project_name: "Neon Genesis")
      report.add_scan_report(scanner.report, required: false)
      sarif = JSON.parse(report.to_sarif({ 'include_non_enforced' => true }))

      # contains rule
      expect(sarif['runs'][0]['tool']['driver']['rules'][0]).to include(
        { "id" => "PV0001",
         "name" => "NPMPackageScanner",
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
         "message" => { "text" => "Package version for (mobx) (3.6.2) is less than minimum" \
         " configured version (3.6.3) on line {13} in package-lock.json." },
         "locations" => [{ "physicalLocation" => {
           "artifactLocation" => { "uri" => "package-lock.json",
         "uriBaseId" => "%SRCROOT%" }, "region" => {
           "startLine" => 13, "startColumn" => 1
         }
         } }],
           "properties" => { "severity" => "HIGH" } }
      )
    end
  end
end
