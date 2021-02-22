require_relative '../../spec_helper.rb'
require 'json-schema'

describe Sarif::BaseSarif do
  let(:scan_report) { Salus::ScanReport.new("Unsupported_Scanner") }
  let(:base_sarif) { Sarif::BaseSarif.new(scan_report) }
  let(:report) { Salus::Report.new(project_name: 'Neon genesis') }
  before do
    scan_report.add_version('1.1.1')
  end

  describe 'tool_info' do
    it 'returns the runs object for an unsupported scanner' do
      expect(base_sarif.build_tool).to include({ "driver":
        {
          "name" => "Unsupported_Scanner",
          "version" => "1.1.1",
          "rules" => [],
          "informationUri" => "https://github.com/coinbase/salus"
        } })
    end
  end

  describe 'conversion' do
    it 'returns the conversion object for the converter (Salus)' do
      expect(base_sarif.build_conversion).to include({ "tool":
        {
          "driver": {
            "name": "Salus",
            "informationUri": "https://github.com/coinbase/salus"
          }
        } })
    end
  end

  describe '#sarif_level' do
    it 'returns a different `low` severity mapping for audit type scanners' do
      non_audit = Salus::ScanReport.new("Gosec")
      adapter = Sarif::GosecSarif.new(non_audit)
      expect(adapter.sarif_level('LOW')).to eq('warning')
      expect(base_sarif.sarif_level('LOW')).to eq('note')
    end
  end

  describe 'sarif_report' do
    it 'returns sarif report' do
      expect(base_sarif.build_runs_object).to include({ "tool" => base_sarif.build_tool,
        "conversion" => base_sarif.build_conversion,
        "results" => [],
        "invocations" => [base_sarif.build_invocations] })
    end
  end
end
