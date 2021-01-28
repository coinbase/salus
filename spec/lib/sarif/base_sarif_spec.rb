require_relative '../../spec_helper.rb'

describe Sarif::BaseSarif do
  let(:scan_report) { Salus::ScanReport.new(scanner_name:"Bandit", version:'1.1.1')}
  let(:base_sarif) {Sarif::BaseSarif.new(scan_report)}
  
  describe'get_tool' do
    it 'returns a Hash with the right fields' do
      puts base_sarif.get_tool
      expected = {
        driver: {
          name: {
            scanner_name: "Bandit", 
            version: "1.1.1"
          }, 
          semanticVersion: "", 
          informationUri: "https://github.com/coinbase/salus"
        }
      }
      expect(base_sarif.get_tool == expected)
    end
  end

  describe 'get_results' do
    it 'returns the default result section for unsupported scanners' do
      expected = {
        "ruleId"  => "SALUS001",
        "message" => {
          "text": "This Scanner does not currently Support SARIF"
        }
      }
      expect(base_sarif.get_results == expected)
    end
  end
end