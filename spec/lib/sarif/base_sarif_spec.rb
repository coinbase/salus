require_relative '../../spec_helper'
require 'json-schema'

describe Sarif::BaseSarif do
  let(:scan_report) { Salus::ScanReport.new("Unsupported_Scanner") }
  let(:base_sarif) { Sarif::BaseSarif.new(scan_report) }
  let(:report) { Salus::Report.new(project_name: 'Neon genesis') }
  before do
    scan_report.add_version('1.1.1')
  end

  describe 'uri_info' do
    it 'should populate SRCROOT' do
      repo_path = 'spec/fixtures/processor'
      repo = Salus::Repo.new("#{repo_path}/recursive")
      report = Salus::ScanReport.new("Unsupported_Scanner", repository: repo)
      sarif = Sarif::BaseSarif.new(report, {}, repo_path)
      info = sarif.uri_info

      expect(info[:PROJECTROOT][:uri]).to end_with(repo_path)
      expect(info[:SRCROOT]).to eq({ uri: "recursive", uriBaseId: "PROJECTROOT" })
    end
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

      it 'does not contain suppressed object when include_suppressed config is false' do
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

      it 'does contain suppressed object when include_suppressed config is true' do
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

      it 'contains active scanner results when include_non_enforced is true' do
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
        adapter.instance_variable_set(:@config, { "include_non_enforced": true }.stringify_keys)
        adapter.instance_variable_set(:@required, false)
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['results'].empty?).to eq(false)
        expect(runs_object["tool"][:driver]["properties"][:salusEnforced]).to be false
        # Make sure supressions are only for suppressed findings and not active findings
        expect(runs_object['results'][0]['suppressions'].nil?).to eq(true)
      end

      it 'does not contain active scanner results when include_non_enforced is false' do
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
        adapter.instance_variable_set(:@config, { "include_non_enforced": false }.stringify_keys)
        adapter.instance_variable_set(:@required, false)
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['results'].empty?).to eq(true)
      end

      it 'contains active scanner results when include_non_enforced is not present' do
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
        adapter.instance_variable_set(:@required, false)
        runs_object = adapter.build_runs_object(true)
        expect(runs_object['results'].empty?).to eq(false)
      end

      it 'includes originalUriBaseIds' do
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

        expect(runs_object.keys).to include("originalUriBaseIds")
        base = runs_object["originalUriBaseIds"]
        expect(base[:PROJECTROOT][:uri]).not_to be_empty
        expect(base[:SRCROOT]).to eq({ uri: ".", uriBaseId: "PROJECTROOT" })
      end
    end
  end

  describe 'salus_passed?' do
    it 'salus_passed? should return false if enforced scanner failed' do
      sarif_file = 'spec/fixtures/sarifs/diff/sarif_2.json'
      sarif = JSON.parse(File.read(sarif_file))
      passed = Sarif::BaseSarif.salus_passed?(sarif)
      expect(passed).to be_falsey
    end

    it 'salus_passed? should return true if non-enforced scanner failed' do
      sarif_file = 'spec/fixtures/sarifs/diff/sarif_1_non_enforced.json'
      sarif = JSON.parse(File.read(sarif_file))
      passed = Sarif::BaseSarif.salus_passed?(sarif)
      expect(passed).to be_truthy
    end

    it 'salus_passed? should return true if all scanners passed' do
      sarif_file = 'spec/fixtures/sarifs/diff/sarif_all_passed.json'
      sarif = JSON.parse(File.read(sarif_file))
      passed = Sarif::BaseSarif.salus_passed?(sarif)
      expect(passed).to be_truthy
    end
  end

  describe 'full sarif diff' do
    it 'diff should have 0 vul with exec success if old sarif includes all vuls in new sarif' do
      # old sarif includes all vuls in new sarif
      # expected_diff has 0 rule/result for each scanner
      #               executionSuccessful for scanner updated to true
      old_sarif_file = 'spec/fixtures/sarifs/diff/sarif_2.json'
      new_sarif_file = 'spec/fixtures/sarifs/diff/sarif_1.json'
      diff_file = 'spec/fixtures/sarifs/diff/sarif_1_2.json'
      old_sarif = JSON.parse(File.read(old_sarif_file))
      new_sarif = JSON.parse(File.read(new_sarif_file))
      diff = Sarif::BaseSarif.report_diff(new_sarif, old_sarif)

      expect { Sarif::SarifReport.validate_sarif(diff) }.not_to raise_error
      expected_diff = JSON.parse(File.read(diff_file))
      expect(expected_diff).to eq(diff)
    end

    it 'diff should include vuls in new sarif that are not in old sarif' do
      # new sarif has 20+ BundleAudit vuls and Brakeman vul
      # old sarif has 2 BundleAudit vuls that are in new sarif, and no Brakeman vul
      # expect diff has the Brakeman vul in new sarif
      #                 and the BundleAudit vuls in new sarif, except the 2 in old sarif
      old_sarif_file = 'spec/fixtures/sarifs/diff/sarif_1.json'
      new_sarif_file = 'spec/fixtures/sarifs/diff/sarif_2.json'
      diff_file = 'spec/fixtures/sarifs/diff/sarif_2_1.json'
      old_sarif = JSON.parse(File.read(old_sarif_file))
      new_sarif = JSON.parse(File.read(new_sarif_file))
      diff = Sarif::BaseSarif.report_diff(new_sarif, old_sarif)

      expect { Sarif::SarifReport.validate_sarif(diff) }.not_to raise_error
      expected_diff = JSON.parse(File.read(diff_file))
      expect(expected_diff).to eq(diff)
    end

    it 'diff should be sarif with no vuls if new sarif == old sarif and old sarif has vuls' do
      old_sarif_file = 'spec/fixtures/sarifs/diff/sarif_1.json'
      new_sarif_file = old_sarif_file
      diff_file = 'spec/fixtures/sarifs/diff/sarif_1_2.json'
      old_sarif = JSON.parse(File.read(old_sarif_file))
      new_sarif = JSON.parse(File.read(new_sarif_file))
      diff = Sarif::BaseSarif.report_diff(new_sarif, old_sarif)

      expect { Sarif::SarifReport.validate_sarif(diff) }.not_to raise_error
      expected_diff = JSON.parse(File.read(diff_file))
      expect(expected_diff).to eq(diff)
    end

    it 'diff should be same as new sarif if new sarif == old sarif and old sarif has no vuls' do
      old_sarif_file = 'spec/fixtures/sarifs/diff/sarif_1_2.json'
      new_sarif_file = old_sarif_file
      diff_file = old_sarif_file
      old_sarif = JSON.parse(File.read(old_sarif_file))
      new_sarif = JSON.parse(File.read(new_sarif_file))
      diff = Sarif::BaseSarif.report_diff(new_sarif, old_sarif)

      expect { Sarif::SarifReport.validate_sarif(diff) }.not_to raise_error
      expected_diff = JSON.parse(File.read(diff_file))
      expect(expected_diff).to eq(diff)
    end

    it 'diff should be same as new sarif if everything passed in new sarif' do
      # if everything passed in new sarif but old sarif has vuls
      # then diff should be the same as new sarif
      old_sarif_file = 'spec/fixtures/sarifs/diff/sarif_1.json' # has vuls
      new_sarif_file = 'spec/fixtures/sarifs/diff/sarif_succ.json' # everything passed
      old_sarif = JSON.parse(File.read(old_sarif_file))
      new_sarif = JSON.parse(File.read(new_sarif_file))
      diff = Sarif::BaseSarif.report_diff(new_sarif, old_sarif)

      expect { Sarif::SarifReport.validate_sarif(diff) }.not_to raise_error
      expect(new_sarif).to eq(diff)
    end

    it 'diff should include vuls with same id but different artifact locations' do
      old_sarif_file = 'spec/fixtures/sarifs/diff/sarif_3.json'
      new_sarif_file = 'spec/fixtures/sarifs/diff/sarif_1.json'
      diff_file = 'spec/fixtures/sarifs/diff/sarif_1_3.json'
      old_sarif = JSON.parse(File.read(old_sarif_file))
      new_sarif = JSON.parse(File.read(new_sarif_file))
      diff = Sarif::BaseSarif.report_diff(new_sarif, old_sarif)

      expect { Sarif::SarifReport.validate_sarif(diff) }.not_to raise_error
      expected_diff = JSON.parse(File.read(diff_file))
      expect(expected_diff).to eq(diff)
    end
  end
end
