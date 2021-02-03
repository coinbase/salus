require_relative '../../spec_helper.rb'
require 'json-schema'

describe Sarif::BaseSarif do
  let(:scan_report) { Salus::ScanReport.new("Bandit") }
  let(:base_sarif) { Sarif::BaseSarif.new(scan_report) }
  let(:report) { Salus::Report.new(project_name: 'Neon genesis') }
  before do
    scan_report.add_version('1.1.1')
  end

  describe 'tool_info' do
    it 'returns the runs object for an unsupported scanner' do
      expect(base_sarif.tool_info).to include({ "driver":
        {
          "name" => "Bandit",
          "version" => "1.1.1"
        } })
    end
  end

  describe 'conversion' do
    it 'returns the conversion object for the converter (Salus)' do
      expect(base_sarif.conversion).to include({ "tool":
        {
          "driver": {
            "name": "Salus",
            "informationUri": "https://github.com/coinbase/salus"
          }
        } })
    end
  end

  describe 'sarif_report' do
    it 'returns' do
      expect(base_sarif.sarif_report).to include({ "tool" => base_sarif.tool_info,
        "conversion" => base_sarif.conversion,
        "results" => [],
        "invocations" => base_sarif.invocations
      })
    end
  end
end
