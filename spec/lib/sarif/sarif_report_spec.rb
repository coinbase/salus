require_relative '../../spec_helper.rb'
require 'json'
require 'json-schema'

describe Sarif::SarifReport do
  let(:scan_report1) { Salus::ScanReport.new(name: 'Unsupported_Scanner') }
  let(:scan_report2) { Salus::ScanReport.new('Gosec') }
  let(:scan_reports) { [scan_report1, scan_report2] }

  describe 'to_sarif' do
    let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }
    let(:name) { 'Neon Genesis Evangelion' }
    let(:custom_info) { { bitcoin_price: 100_000 } }
    let(:config) { { lemurs: 'contained', raptors: 'loose' } }
    let(:report) { Salus::Report.new(project_name: name, custom_info: custom_info, config: config) }

    before do
      scan_reports.each do |scan_report|
        scan_report.add_version('')
        report.add_scan_report(scan_report, required: false)
      end
    end

    it 'fails if generated sarif format is incorrect' do
      expect { report.to_sarif }.to raise_error(
        Sarif::SarifReport::SarifInvalidFormatError,
        'Incorrect Sarif Output'
      )
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
      expect(report1["driver"]['name']).to eq('Unsupported_Scanner')
      expect(report2['driver']['name']).to eq('Gosec')
    end
  end
end
