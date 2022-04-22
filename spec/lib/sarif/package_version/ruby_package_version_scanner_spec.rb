require_relative '../../../spec_helper'
require 'json'

describe Sarif::RubyPackageScannerSarif do
  let(:path) { 'spec/fixtures/package_version/ruby_package_version_scanner/' }
  let(:config_file) { YAML.load_file("#{path}/salus_fail_with_range.yml") }
  let(:scanner_config) { config_file['scanner_configs']["RubyPackageScanner"] }

  context 'ruby package version mismatch' do
    let(:repo) { Salus::Repo.new('spec/fixtures/bundle_audit/cves_found') }
    it 'should generate error in report' do
      scanner = Salus::Scanners::PackageVersion::RubyPackageScanner.new(repository: repo,
      config: scanner_config)
      url = "https://github.com/coinbase/salus/blob/master/docs/scanners/package_version_scan.md"
      scanner.run
      report = Salus::Report.new(project_name: "Neon Genesis")
      report.add_scan_report(scanner.report, required: false)
      sarif = JSON.parse(report.to_sarif({ 'include_non_enforced' => true }))

      # contains rule
      expect(sarif['runs'][0]['tool']['driver']['rules'][0]).to include(
        { "id" => "PV0001",
         "name" => "RubyPackageScanner",
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
         "message" => { "text" => "Package version for (actionmailer) (4.1.15) is greater"\
            " than maximum configured version (3.0.0) in Gemfile.lock." },
         "locations" => [{ "physicalLocation" => {
           "artifactLocation" => { "uri" => "Gemfile.lock",
         "uriBaseId" => "%SRCROOT%" }
         } }],
           "properties" => { "severity" => "HIGH" } }
      )
    end
  end
end
