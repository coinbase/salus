require_relative '../../spec_helper'
require 'json'

describe Sarif::YarnAuditSarif do
  let(:stub_stdout_failure_2) do
    File.read('spec/fixtures/yarn_audit/failure-2/stub_stdout.txt')
  end
  let(:stub_stderr_failure_2) { "" }
  let(:stub_status_failure_2) { 26 }
  let(:stub_stdout_failure_4) do
    File.read('spec/fixtures/yarn_audit/failure-4/stub_stdout.txt')
  end
  let(:stub_stderr_failure_4) { "" }
  let(:stub_status_failure_4) { 28 }

  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::YarnAudit.new(repository: repo, config: {}) }
    let(:error_id_fail_2) { "1002899" } # was 39 before the great yarn advisory reshuffling of '21

    context 'scan report with logged vulnerabilites' do
      let(:path) { 'spec/fixtures/yarn_audit/failure-2' }
      let(:repo) { Salus::Repo.new(path) }
      it 'parses information correctly' do
        status = ProcessStatusDouble.new(stub_status_failure_2)
        stub_ret = Salus::ShellResult.new(stub_stdout_failure_2, stub_stderr_failure_2, status)
        allow(scanner).to receive(:version).and_return('1.22.0')
        allow(scanner).to receive(:run_shell).and_return(stub_ret)

        scanner.run
        issue = JSON.parse(scanner.report.to_h[:info][:stdout])[0]
        yarn_sarif = Sarif::YarnAuditSarif.new(scanner.report, path)

        expect(yarn_sarif.parse_issue(issue)).to include(
          id: "1005415",
          name: "Prototype Pollution in merge",
          level: "HIGH",
          details: "Prototype Pollution in merge, Dependency of: merge",
          messageStrings: {
            dependency_of: { text: "merge" },
            package: { text: "merge" },
            patched_versions: { text: ">=2.1.1" },
            severity: { text: "high" }
          },
          uri: "yarn.lock",
          help_url: "https://www.npmjs.com/advisories/1005415",
          start_line: 21,
          start_column: 1,
          properties: { severity: "high" }
        )
      end
    end
  end

  describe '#sarif_report' do
    let(:scanner) { Salus::Scanners::YarnAudit.new(repository: repo, config: {}) }

    context 'Yarn file with errors' do
      let(:path) { 'spec/fixtures/yarn_audit/failure-3' }
      let(:repo) { Salus::Repo.new(path) }
      it 'should generate error in report' do
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(false)

        message = report_object['invocations'][0]['toolExecutionNotifications'][0]['message']
        expect(message['text']).to eq("==== Salus Errors\n[\n  {\n    \"status\": 1,\n    "\
          "\"message\": \"error Received malformed response from registry for"\
          " \\\"classnames-repo-does-not-exist\\\". The registry may be down.\\n\"\n  }\n]")
      end
    end

    context 'Yarn file with no vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/yarn_audit/success') }
      it 'should generate an empty sarif report' do
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]

        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'yarn project with vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/yarn_audit/failure-4') }
      let(:error_id_fail_4) { "1004708" } # was 39 before the great yarn advisory reshuffling of '21

      it 'should generate the right results and rules' do
        status = ProcessStatusDouble.new(stub_status_failure_4)
        stub_ret = Salus::ShellResult.new(stub_stdout_failure_4, stub_stderr_failure_4, status)
        allow(scanner).to receive(:version).and_return('1.22.0')
        allow(scanner).to receive(:run_shell).and_return(stub_ret)

        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)

        parsed_json = JSON.parse(report.to_sarif({ 'include_active' => true }))

        result = parsed_json["runs"][0]["results"].first
        rule = parsed_json["runs"][0]["tool"]["driver"]["rules"].first

        # Check rule info
        expect(rule['id']).to eq("1005365")
        expect(rule['name']).to eq("Command Injection in lodash")
        expect(rule['fullDescription']['text']).to eq("Command Injection in lodash")
        expect(rule['helpUri']).to eq("https://www.npmjs.com/advisories/1005365")

        # Check result info
        expect(result['ruleId']).to eq("1005365")
        expect(result['ruleIndex']).to be >= 0 # liberal here to avoid hard coding the index
        expect(result['level']).to eq('error')

        region = result['locations'][0]['physicalLocation']['region']
        expect(region['startLine']).to eq(21)
        expect(region['startColumn']).to eq(1)
      end
    end

    context 'yarn.lock file with vulnerabilities having the same ID' do
      let(:path) { 'spec/fixtures/yarn_audit/failure-2' }
      let(:repo) { Salus::Repo.new(path) }
      it 'should generate all identified vulnerabilities' do
        scanner.run
        issue = JSON.parse(scanner.report.to_h[:info][:stdout])[0]
        yarn_sarif = Sarif::YarnAuditSarif.new(scanner.report, path)

        issue2 = issue.clone
        issue2['Dependency of'] = 'random package'

        expect(yarn_sarif.parse_issue(issue2).nil?).to eq(false)
        expect(yarn_sarif.parse_issue(issue).nil?).to eq(false)
        expect(yarn_sarif.parse_issue(issue).nil?).to eq(true)
      end
    end
  end

  describe '#sarif_level' do
    it 'maps severities to the right sarif level' do
      scan_report = Salus::ScanReport.new('yarnaudit')
      adapter = Sarif::YarnAuditSarif.new(scan_report)
      expect(adapter.sarif_level("INFO")).to eq("note")
      expect(adapter.sarif_level("LOW")).to eq("note")
      expect(adapter.sarif_level("MODERATE")).to eq("warning")
      expect(adapter.sarif_level("HIGH")).to eq("error")
      expect(adapter.sarif_level("CRITICAL")).to eq("error")
    end
  end

  describe 'sarif diff' do
    context 'git diff support' do
      let(:new_lines_in_git_diff) do
        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_yarn.txt'
        git_diff = File.read(git_diff_file)
        Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
      end

      it 'should find code in git diff' do
        snippet = 'jspdf'
        r = Sarif::YarnAuditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true
        snippet = 'text-segmentation'
        r = Sarif::YarnAuditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true
      end

      it 'should not match part of the package name' do
        snippet = 'jspd'
        r = Sarif::YarnAuditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be false
      end

      it 'should not match package that was in git diff but not added with this commit' do
        snippet = 'fuubar'
        r = Sarif::YarnAuditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be false
      end
    end
  end
end
