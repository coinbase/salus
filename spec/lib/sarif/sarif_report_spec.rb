require_relative '../../spec_helper.rb'
require 'json'
require 'json-schema'

describe Sarif::SarifReport do
  let(:name1) { 'Unsupported_Scanner' }
  let(:name2) { 'Gosec' }
  let(:scan_report1) { Salus::ScanReport.new(scanner_name: name1, version: '1.1.1') }
  let(:scan_report2) { Salus::ScanReport.new(scanner_name: name2, version: '0.0.1') }
  let(:scan_reports) { [scan_report1, scan_report2] }
  let(:sarif_report) { Sarif::SarifReport.new(scan_reports) }

  describe 'to_sarif' do
    it 'it returns a sarif report with all ScanReports' do
      schema = JSON.parse(File.read('spec/fixtures/sarif/sarif-schema.json'))

      body = JSON.parse(sarif_report.to_sarif)
      report1 = body['runs'][0]['tool']
      report2 = body['runs'][1]['tool']
      expect(JSON::Validator.validate(schema, body)).to be true
      expect(report1["driver"]['name']).to eq('Unsupported_Scanner')
      expect(report2['driver']['name'].downcase).to eq('GoSec'.downcase)
    end
  end

  describe 'converter' do
    context 'Instantiates BaseSarif for unsupported scanners' do
      it 'should return the default sarif report' do
        report1 = JSON.parse(JSON.pretty_generate(sarif_report.converter(scan_report1)))
        expect(report1['tool']['driver']['version']).to eq('1.1.1')
        expect(report1['tool']['driver']['name']).to eq('Unsupported_Scanner')
      end
    end
  end
end
