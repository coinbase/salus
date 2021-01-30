require_relative '../../spec_helper.rb'
require 'json'
require 'json-schema'

describe Sarif::SarifReport do
  let(:scan_report1) { Salus::ScanReport.new('Unsupported_Scanner') }
  let(:scan_report2) { Salus::ScanReport.new('Gosec') }
  let(:scan_reports) { [scan_report1, scan_report2] }

  describe 'to_sarif' do
    let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }

    it 'it returns a sarif report with all ScanReports' do
      name = 'Neon Genesis Evangelion'
      custom_info = { bitcoin_price: 100_000 }
      config = { lemurs: 'contained', raptors: 'loose' }
      report = Salus::Report.new(project_name: name, custom_info: custom_info, config: config)
      scan_reports.each { |scan_report| report.add_scan_report(scan_report, required: false) }
      schema = JSON.parse(File.read('spec/fixtures/sarif/sarif-schema.json'))

      body = JSON.parse(report.to_sarif)
      report1 = body['runs'][0]['tool']
      report2 = body['runs'][1]['tool']
      expect(JSON::Validator.validate(schema, body)).to be true
      expect(report1["driver"]['name']).to eq('Unsupported_Scanner')
      expect(report2['driver']['name']).to eq('Gosec')
    end
  end
end
