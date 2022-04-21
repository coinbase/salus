require_relative '../../spec_helper'

describe Sarif::BanditSarif do
  describe '#parse_issue' do
    let(:py_dir) { 'spec/fixtures/python' }
    let(:scanner) { Salus::Scanners::Bandit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'scan report with logged vulnerabilites' do
      let(:path) { "#{py_dir}/python_project_with_insecure_code_practices" }
      let(:repo) { Salus::Repo.new(path) }
      it 'parses information correctly' do
        bandit_sarif = Sarif::BanditSarif.new(scanner.report, path)
        issue = JSON.parse(scanner.log(''))['results'][0]

        expected = "1 import cPickle\n2 import pickle\n3 import StringIO\n"

        expect(bandit_sarif.parse_issue(issue)).to include(
          id: "B403",
          name: "blacklist",
          level: "LOW",
          details: "Consider possible security implications associated with cPickle module.",
          messageStrings: { "confidence": { "text": "LOW" },
                           "severity": { "text": "LOW" } },
          properties: { "severity": "LOW" },
          start_line: 1,
          start_column: 1,
          help_url: "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html"\
          "#b403-import-pickle",
          code: expected
        )
      end

      it 'dont have duplicate entries' do
        bandit_sarif = Sarif::BanditSarif.new(scanner.report, path)
        issue = JSON.parse(scanner.log(''))['results'][0]

        expect(bandit_sarif.parse_issue(issue).nil?).to eq(false)
        expect(bandit_sarif.parse_issue(issue).nil?).to eq(true)
      end
    end
  end

  describe '#sarif_level' do
    let(:scanner) { Salus::Scanners::Bandit.new(repository: repo, config: {}) }
    let(:py_dir) { 'spec/fixtures/python' }
    let(:path) { "#{py_dir}/python_project_no_vulns" }

    context 'Bandit Severities' do
      let(:repo) { Salus::Repo.new(path) }

      it 'are mapped to the right sarif levels' do
        adapter = Sarif::BanditSarif.new(scanner.report, path)
        expect(adapter.sarif_level("HIGH")).to eq("error")
        expect(adapter.sarif_level("LOW")).to eq("warning")
        expect(adapter.sarif_level("MEDIUM")).to eq("error")
      end
    end
  end

  describe '#sarif_report' do
    let(:py_dir) { 'spec/fixtures/python' }
    let(:scanner) { Salus::Scanners::Bandit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'non python project' do
      let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }
      it 'reports an error for non python projects' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)

        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(false)
        message = report_object['invocations'][0]['toolExecutionNotifications'][0]['message']
        expect(message['text']).to include('0 lines of code were scanned')
      end
    end

    context 'python project with no vulnerabilities' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_no_vulns") }

      it 'should have an empty sarif report for successful scans' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]

        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'python project with empty report containing whitespace' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_no_vulns") }
      it 'should handle empty reports with whitespace' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        # Override the report.log() to return "\n"
        report.class.send(:define_method, :log, -> { "\n" })
        expect_any_instance_of(Sarif::BanditSarif).not_to receive(:bugsnag_notify)

        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'python project with vulnerabilities' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_with_insecure_code_practices_r") }
      it 'should record 0 line of code scanned if no code' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        sarif = JSON.parse(report.to_sarif({ 'include_non_enforced' => true }))
        result = sarif["runs"][0]["results"][-2]
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        # Check rule info
        expect(rules[0]['id']).to eq('B403')
        expect(rules[0]['name']).to eq('blacklist')
        expect(rules[0]['fullDescription']['text']).to include("Consider possible security"\
          " implications associated with cPickle module.")
        expect(rules[0]['helpUri']).to eq("https://bandit.readthedocs.io/en/latest/"\
          "blacklists/blacklist_imports.html#b403-import-pickle")

        # Check result info
        expect(result['ruleId']).to eq('B403')
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('warning')
        expect(result['locations'][0]['physicalLocation']['region']['startLine']).to eq(1)
        expected = "1 import cPickle\n2 import pickle\n3 import StringIO\n"
        snippet = result['locations'][0]['physicalLocation']['region']['snippet']['text'].to_s
        expect(snippet).to eq(expected)
      end
    end
  end

  describe 'sarif diff' do
    context 'git diff support' do
      it 'should find code in git diff' do
        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_4.txt'
        snippet = "2 \n3 self.process = subprocess.Popen('/bin/echo', shell=True)\n4 foo()\n"
        git_diff = File.read(git_diff_file)
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::BanditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true

        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_5.txt'
        snippet = "2 \n3 self.process = subprocess.Popen('/bin/echo', shell=True)\n4 foo()\n"
        git_diff = File.read(git_diff_file)
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::BanditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true

        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_5.txt'
        snippet = "2 \n3 self.process = subprocess.Popen('/bin/echo', shell=True)\n4 baz()\n"
        git_diff = File.read(git_diff_file)
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::BanditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be false
      end
    end
  end
end
