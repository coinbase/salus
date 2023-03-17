require_relative '../../spec_helper'
require 'json'
require 'json-schema'

describe Sarif::SarifReport do
  let(:scan_report1) { Salus::ScanReport.new('Unsupported_Scanner') }
  let(:scan_report2) { Salus::ScanReport.new('Neon_Scanner') }
  let(:scan_reports) { [scan_report1, scan_report2] }

  describe 'to_sarif' do
    let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }
    let(:name) { 'Neon Genesis Evangelion' }
    let(:custom_info) { { bitcoin_price: 100_000 } }
    let(:config) { { lemurs: 'contained', raptors: 'loose' } }
    let(:build) { { "url": "https://github.com" } }
    let(:report) { Salus::Report.new(project_name: name, custom_info: custom_info, builds: build) }

    before do
      scan_reports.each do |scan_report|
        scan_report.add_version('')
        report.add_scan_report(scan_report, required: false)
      end
    end

    it 'fails if generated sarif format is incorrect' do
      scanner = Salus::Scanners::RepoNotEmpty.new(repository: repo, config: {})
      scanner.run
      report.add_scan_report(scanner.report, required: false)
      expect(report).to receive(:bugsnag_notify).with("Sarif::SarifReport::SarifInvalidFormatError Incorrect Sarif Output: foo\nBuild Info:{:url=>\"https://github.com\"}")
      expect(JSON::Validator).to receive(:validate).and_return(false)
      expect(JSON::Validator).to receive(:fully_validate).and_return("foo")

      report.to_sarif
    end

    it 'contains the right scanners' do
      report = Salus::Report.new(project_name: name, custom_info: custom_info, config: config)
      scan_reports[0] = Salus::ScanReport.new('Unsupported_Scanner')
      scan_reports.each do |scan_report|
        scan_report.add_version('')
        report.add_scan_report(scan_report, required: false)
      end
      body = JSON.parse(report.to_sarif)
      report1 = body['runs'][0]['tool']
      report2 = body['runs'][1]['tool']
      expect(report1['driver']['name']).to eq('Neon_Scanner')
      expect(report2["driver"]['name']).to eq('Unsupported_Scanner')
    end
  end
end
