require_relative '../../spec_helper'
require 'json'
require 'json-schema'

describe Sarif::GosecSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::Gosec.new(repository: repo, config: {}) }
    let(:path) { 'spec/fixtures/gosec/safe_goapp' }
    before { scanner.run }

    context 'scan report with duplicate vulnerabilities' do
      let(:repo) { Salus::Repo.new(path) }
      let(:path) { 'spec/fixtures/gosec/duplicate_entries' }
      it 'should not include duplicate result entries' do
        scan_report = Salus::ScanReport.new(scanner_name: "Gosec")
        f = File.read("#{path}/report.json")
        scan_report.log(f.to_s)
        adapter = Sarif::GosecSarif.new(scan_report, path)
        results = adapter.build_runs_object(true)["results"]
        expect(results.size).to eq(3)
        unique_results = Set.new
        results.each do |result|
          expect(unique_results.include?(result)).to eq(false)
          unique_results.add(result)
        end
      end

      it 'should not include duplicate rules' do
        scan_report = Salus::ScanReport.new(scanner_name: "Gosec")
        f = File.read('spec/fixtures/gosec/duplicate_entries/report.json')
        scan_report.log(f.to_s)
        adapter = Sarif::GosecSarif.new(scan_report, 'spec/fixtures/gosec/duplicate_entries')
        rules = adapter.build_runs_object(true)["tool"][:driver]["rules"]
        expect(rules.size).to eq(2)
        unique_rules = Set.new
        rules.each do |rule|
          expect(unique_rules.include?(rule)).to eq(false)
          unique_rules.add(rule)
        end
      end
    end

    describe '#sarif_level' do
      context 'gosec severities' do
        let(:path) { 'spec/fixtures/gosec/safe_goapp' }
        let(:repo) { Salus::Repo.new(path) }
        it 'are mapped to sarif levels' do
          scan_report = Salus::ScanReport.new(scanner_name: "Gosec")
          adapter = Sarif::GosecSarif.new(scan_report, path)
          expect(adapter.sarif_level("MEDIUM")).to eq("error")
          expect(adapter.sarif_level("HIGH")).to eq("error")
          expect(adapter.sarif_level("LOW")).to eq("warning")
        end
      end
    end

    context 'scan report with logged vulnerabilites' do
      let(:path) { 'spec/fixtures/gosec/vulnerable_goapp' }
      let(:repo) { Salus::Repo.new(path) }
      it 'parses information correctly' do
        gosec_sarif = Sarif::GosecSarif.new(scanner.report, path)
        issue = JSON.parse(scanner.log(''))['Issues'][0]

        # should Parse and fill out hash
        expected = "7: func test2() {\n8: \tpassword := \"hhend77dyyydbh&^psNSSZ)JSM--_%\"\n9: "\
        "\tfmt.Println(\"hello, from the vulnerable app\" + password)\n"
        expect(gosec_sarif.parse_issue(issue)).to include(
          id: "G101",
          name: "CWE-798",
          level: "HIGH",
          details: "Potential hardcoded credentials \nSeverity: HIGH\nConfidence: LOW\nCWE: "\
          "https://cwe.mitre.org/data/definitions/798.html",
          messageStrings: { "severity": { "text": "HIGH" },
                           "confidence": { "text": "LOW" },
                           "cwe": { "text": "https://cwe.mitre.org/data/definitions/798.html" } },
          start_line: 8,
          start_column: 2,
          help_url: "https://cwe.mitre.org/data/definitions/798.html",
          uri: "hello.go",
          properties: { severity: "HIGH" },
          code: expected
        )
      end
    end
  end

  describe '#sarif_report' do
    let(:scanner) { Salus::Scanners::Gosec.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'non go project' do
      let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }
      it 'should handle generated error' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(false)

        message = report_object['invocations'][0]['toolExecutionNotifications'][0]['message']
        expect(message['text']).to include('0 lines of code were scanned')
      end
    end

    context 'go project with no vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/safe_goapp') }
      it 'should generate an empty sarif report' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]

        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'go project with empty report containing whitespace' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/safe_goapp') }
      it 'should handle empty reports with whitespace' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        # Override the report.log() to return "\n"
        report.class.send(:define_method, :log, -> { "\n" })
        expect_any_instance_of(Sarif::GosecSarif).not_to receive(:bugsnag_notify)

        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'go project with errors' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/malformed_goapp') }
      it 'should parse golang errors' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        sarif = JSON.parse(report.to_sarif({ 'include_non_enforced' => true }))
        result = sarif["runs"][0]["results"][0]
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]

        expect(rules[0]['id']).to eq('SAL002')
        expect(rules[0]['name']).to eq('Golang Error')
        expect(rules[0]['fullDescription']['text']).to eq("errors reported by scanner")
        expect(rules[0]['helpUri']).to eq('https://github.com/coinbase/salus/blob/master/docs/salus_reports.md')

        expect(result['ruleId']).to eq('SAL002')
        expect(result['ruleIndex']).to eq(0)
        expect(result['message']['text']).to eq('Pintl not declared by package fmt')
        expect(result['level']).to eq('note')
        expect(result['locations'][0]['physicalLocation']['region']['startLine']).to eq(8)
      end
    end

    context 'go project with vulnerabilities' do
      let(:path) { 'spec/fixtures/gosec/recursive_vulnerable_goapp' }
      let(:repo) { Salus::Repo.new(path) }

      it 'should generate the right results and rules' do
        report = Salus::Report.new(project_name: "Neon Genesis", repo_path: path)
        report.add_scan_report(scanner.report, required: false)
        sarif = JSON.parse(report.to_sarif({ 'include_non_enforced' => true }))
        result = sarif["runs"][0]["results"][0]
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        # Check rule info
        expect(rules[0]['id']).to eq('G101')
        expect(rules[0]['name']).to eq('CWE-798')
        expect(rules[0]['fullDescription']['text']).to eq("Potential hardcoded credentials "\
        "\nSeverity: HIGH\nConfidence: LOW\nCWE: https://cwe.mitre.org/data/definitions/798.html")
        expect(rules[0]['helpUri']).to eq('https://cwe.mitre.org/data/definitions/798.html')

        # Check result info
        expect(result['ruleId']).to eq('G101')
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('error')
        expect(result['locations'][0]['physicalLocation']['region']['startLine']).to eq(8)
        expect(result['locations'][0]['physicalLocation']['region']['startColumn']).to eq(2)
        expected = "7: func main() {\n8: \tpassword := \"hhend77dyyydbh&^psNSSZ)JSM--_%\"\n9: "\
        "\tfmt.Println(\"hello, from the vulnerable app\" + password)\n"
        snippet = result['locations'][0]['physicalLocation']['region']['snippet']['text'].to_s
        expect(snippet).to eq(expected)
      end
    end
  end

  describe 'sarif diff' do
    context 'git diff support' do
      it 'should find code in git diff' do
        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_1.txt'
        snippet = "6:     username := \"admin\"\n7:     var password = " \
                  "\"f62e5bcda4fae4f82370da0c6f20697b8f8447ef\"\n8: \n"
        git_diff = File.read(git_diff_file)
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::GosecSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true

        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_2.txt'
        snippet = "6:     username := \"admin\"\n7:     var password = " \
                  "\"f62e5bcda4fae4f82370da0c6f20697b8f8447ef\"\n8: \n"
        git_diff = File.read(git_diff_file)
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::GosecSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true

        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_2.txt'
        snippet = "6:     username := \"admin123\"\n7:     var password = " \
                  "\"f62e5bcda4fae4f82370da0c6f20697b8f8447ef\""
        git_diff = File.read(git_diff_file)
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::GosecSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be false

        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_2.txt'
        snippet = "6:     username := \"admin123\"\n7:     var password = " \
                  "\"f62e5bcda4fae4f82370da0c6f20697b8f8447ef\"\n8: \n"
        git_diff = File.read(git_diff_file)
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::GosecSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be false
      end
    end
  end
end
