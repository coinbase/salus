require_relative '../../spec_helper.rb'
require 'json'

describe Sarif::SarifReport do
  let(:scan_report1) { Salus::ScanReport.new(scanner_name:"Unsupported_Scanner", version:'1.1.1')}
  let(:scan_report2) { Salus::ScanReport.new(scanner_name:"GoSec", version:'0.0.1')}
  let(:scan_reports) { [scan_report1, scan_report2]}
  let(:sarif_report) {Sarif::SarifReport.new(scan_reports)}
  
  describe'to_sarif' do
    it 'it returns a sarif report with all ScanReports' do
      
      body = JSON.parse(sarif_report.to_sarif)
      report1 = body['runs'][0]['tool']
      report2 = body['runs'][1]['tool']
      
      expect(body['version']).to eq('2.1.0')
      expect(body['$schema']).to eq('https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json')
      
      expect(report1["driver"]['name']['scanner_name']).to eq('Unsupported_Scanner')
      expect(report2['driver']['name']['scanner_name']).to eq('GoSec')
    end
  end

  describe'converter' do
    context 'Instantiates adapters for supported scanners' do
      it 'should return the a modified sarif report for Gosec scanner' do
        report2 = JSON.parse(JSON.pretty_generate(sarif_report.converter(scan_report2)))
        expect(report2['tool']['driver']['name']['version']).to eq('0.0.1')
        expect(report2['tool']['driver']['name']['scanner_name']).to eq('GoSec')
        expect(report2['tool']['driver']['informationUri']).to eq('https://github.com/securego/gosec')
      end
    end
    
    context 'Instantiates BaseSarif for unsupported scanners' do
      it 'should return the default sarif report' do
        report1 = JSON.parse(JSON.pretty_generate(sarif_report.converter(scan_report1)))
        expect(report1['tool']['driver']['name']['version']).to eq('1.1.1')
        expect(report1['tool']['driver']['name']['scanner_name']).to eq('Unsupported_Scanner')
        expect(report1['tool']['driver']['informationUri']).to eq('https://github.com/coinbase/salus')
      
        expect(report1['result']['message']['text']).to eq("This Scanner does not currently Support SARIF")
      end
    end
  end
end