require_relative '../../spec_helper.rb'

describe Sarif::BaseSarif do
  let(:scan_report) { Salus::ScanReport.new(scanner_name: "Bandit", version: '1.1.1') }
  let(:base_sarif) { Sarif::BaseSarif.new(scan_report) }

  describe 'tool_info' do
    it 'returns a Hash with the right fields' do
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
      expect(base_sarif.tool_info == expected)
    end
  end

  describe 'results' do
    it 'returns the default result section for unsupported scanners' do
      expected = {
        "ruleId"  => "SALUS001",
        "message" => {
          "text": "This Scanner does not currently Support SARIF"
        }
      }
      expect(base_sarif.results_info == expected)
    end
  end
end
