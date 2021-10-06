require_relative '../../spec_helper'
require 'json-schema'

describe Sarif::BaseSarif do
  let(:scan_report) { Salus::ScanReport.new("Unsupported_Scanner") }
  let(:base_sarif) { Sarif::BaseSarif.new(scan_report, "./") }
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
          "informationUri" => "https://github.com/coinbase/salus",
          "properties" => {
            "salusEnforced": false
          }
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

  describe 'sarif_report' do
    it 'returns' do
      expect(base_sarif.build_runs_object(false)).to include({ "tool" => base_sarif.build_tool,
        "conversion" => base_sarif.build_conversion,
        "results" => [],
        "invocations" => [base_sarif.build_invocations(scan_report, false)] })
    end
  end

  describe '#build_runs_object' do
    context 'results object' do
      let(:path) { "./" }
      it 'has suppressions objects for suppressed results' do
        parsed_issue = {
          id: 'SAL002',
          name: "Golang Error",
          level: "NOTE",
          details: 'error',
          start_line: 1,
          start_column: 1,
          uri: '',
          help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md",
          code: "",
          suppressed: true
        }
        adapter = Sarif::GosecSarif.new(scan_report, path)
        adapter.instance_variable_set(:@logs, [parsed_issue])
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['results'][0]['suppressions'].nil?).to eq(false)
      end

      it 'does not contain suppressed object when suppressed key is not present' do
        parsed_issue = {
          id: 'SAL002',
          name: "Golang Error",
          level: "NOTE",
          details: 'error',
          start_line: 1,
          start_column: 1,
          uri: '',
          help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md",
          code: ""
        }
        adapter = Sarif::GosecSarif.new(scan_report, path)
        adapter.instance_variable_set(:@logs, [parsed_issue])
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['results'][0]['suppressions'].nil?).to eq(true)
      end

      it 'does not contain suppressed object when includes_suppresd config is false' do
        parsed_issue = {
          id: 'SAL002',
          name: "Golang Error",
          level: "NOTE",
          details: 'error',
          start_line: 1,
          start_column: 1,
          uri: '',
          help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md",
          code: "",
          suppressed: true
        }
        adapter = Sarif::GosecSarif.new(scan_report, path)
        adapter.instance_variable_set(:@logs, [parsed_issue])
        adapter.instance_variable_set(:@config, { "include_suppressed": false }.stringify_keys)
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['results'].empty?).to eq(true)
      end

      it 'does contains suppressed object when includes_suppresd config is true' do
        parsed_issue = {
          id: 'SAL002',
          name: "Golang Error",
          level: "NOTE",
          details: 'error',
          start_line: 1,
          start_column: 1,
          uri: '',
          help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md",
          code: "",
          suppressed: true
        }
        adapter = Sarif::GosecSarif.new(scan_report, path)
        adapter.instance_variable_set(:@logs, [parsed_issue])
        adapter.instance_variable_set(:@config, { "include_suppressed": true }.stringify_keys)
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['results'].empty?).to eq(false)
      end

      it 'has a suppression object when scanner is not enforced and suppressions are included' do
        parsed_issue = {
          id: 'SAL002',
          name: "Golang Error",
          level: "NOTE",
          details: 'error',
          start_line: 1,
          start_column: 1,
          uri: '',
          help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md",
          code: ""
        }
        adapter = Sarif::GosecSarif.new(scan_report, path)
        adapter.instance_variable_set(:@logs, [parsed_issue])
        adapter.instance_variable_set(:@config, { "include_suppressed": true }.stringify_keys)
        adapter.instance_variable_set(:@required, false)
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['results'].empty?).to eq(false)
        expect(runs_object["invocations"][0][:executionSuccessful]).to eq(false)
      end

      it 'has salusEnforced false when supported scanner is not enforced' do
        parsed_issue = {
          id: 'SAL002',
          name: "Golang Error",
          level: "NOTE",
          details: 'error',
          start_line: 1,
          start_column: 1,
          uri: '',
          help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md",
          code: ""
        }
        adapter = Sarif::GosecSarif.new(scan_report, path)
        adapter.instance_variable_set(:@logs, [parsed_issue])
        adapter.instance_variable_set(:@config, { "include_suppressed": true }.stringify_keys)
        adapter.instance_variable_set(:@required, false)
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['tool'][:driver]['properties'][:salusEnforced]).to eq(false)
      end

      it 'has salusEnforced true when supported scanner is enforced' do
        parsed_issue = {
          id: 'SAL002',
          name: "Golang Error",
          level: "NOTE",
          details: 'error',
          start_line: 1,
          start_column: 1,
          uri: '',
          help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md",
          code: ""
        }
        adapter = Sarif::GosecSarif.new(scan_report, path)
        adapter.instance_variable_set(:@logs, [parsed_issue])
        adapter.instance_variable_set(:@config, { "include_suppressed": false }.stringify_keys)
        adapter.instance_variable_set(:@required, true)
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['tool'][:driver]['properties'][:salusEnforced]).to eq(true)
      end

      it 'results are not included for non enforced scanners when include_suppressed is false' do
        parsed_issue = {
          id: 'SAL002',
          name: "Golang Error",
          level: "NOTE",
          details: 'error',
          start_line: 1,
          start_column: 1,
          uri: '',
          help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md",
          code: ""
        }
        adapter = Sarif::GosecSarif.new(scan_report, path)
        adapter.instance_variable_set(:@logs, [parsed_issue])
        adapter.instance_variable_set(:@config, { "include_suppressed": false }.stringify_keys)
        adapter.instance_variable_set(:@required, false)
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['results'].empty?).to eq(true)
      end
    end
  end
end
