require_relative '../../spec_helper'
require 'json'

describe Sarif::NPMAuditSarif do
  let(:stub_stdout_failure_2) do
    JSON.parse(File.read('spec/fixtures/npm_audit/failure-2/stub_stdout.txt'))
  end
  let(:stub_stderr_failure_2) do
    JSON.parse(File.read('spec/fixtures/npm_audit/failure-2/stub_stderr.txt'))
  end

  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::NPMAudit.new(repository: repo, config: {}) }

    context 'scan report with logged vulnerabilites' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/failure-2') }
      it 'parses information correctly' do
        status = ProcessStatusDouble.new(1)
        stub_ret = Salus::ShellResult.new(stub_stdout_failure_2, stub_stderr_failure_2, status)
        allow(scanner).to receive(:run_shell).and_return(stub_ret)

        scanner.run

        issues = scanner.report.to_h[:info][:stdout][:advisories].values
        issue = issues.first
        npm_sarif = Sarif::NPMAuditSarif.new(scanner.report, './')
        parsed_issue = npm_sarif.parse_issue(issue)

        expect(parsed_issue).to include(
          id: "1005415",
          name: "Prototype Pollution in merge",
          level: "HIGH",
          messageStrings: { "cwe": { "text": "CWE-915" },
                            "package": { "text": "merge" },
                            "patched_versions": { "text": ">=2.1.1" },
                            "recommendation": { "text": "Upgrade to version 2.1.1 or later" },
                            "severity": { "text": "high" },
                            "vulnerable_versions": { "text": "<2.1.1" } },
          help_url: "https://github.com/advisories/GHSA-7wpw-2hjm-89gp",
          uri: "package-lock.json",
          properties: { severity: "high" },
          suppressed: false
        )
        expected_details = "All versions of package merge <2.1.1 are vulnerable to Prototype"
        expect(parsed_issue[:details]).to include(expected_details)
      end
    end

    context 'Duplicate advisories' do
      let(:path) { 'spec/fixtures/npm_audit/failure-2' }
      let(:repo) { Salus::Repo.new(path) }
      it 'should be parsed once' do
        status = ProcessStatusDouble.new(1)
        stub_ret = Salus::ShellResult.new(stub_stdout_failure_2, stub_stderr_failure_2, status)
        allow(scanner).to receive(:run_shell).and_return(stub_ret)

        scanner.run

        issue = scanner.report.to_h[:info][:stdout][:advisories].values[0]

        npm_sarif = Sarif::NPMAuditSarif.new(scanner.report, path)
        expect(npm_sarif.parse_issue(issue).empty?).to eq(false)
        expect(npm_sarif.parse_issue(issue)).to eq(nil)
      end
    end
  end

  describe '#sarif_level' do
    let(:scanner) { Salus::Scanners::NPMAudit.new(repository: repo, config: {}) }
    before { scanner.run }
    context 'NPM severities' do
      let(:path) { 'spec/fixtures/npm_audit/success' }
      let(:repo) { Salus::Repo.new(path) }
      it 'should be mapped to the right sarif levels' do
        # NPM Severities: https://docs.npmjs.com/about-audit-reports#severity
        adapter = Sarif::NPMAuditSarif.new(scanner.report, path)

        expect(adapter.sarif_level('CRITICAL')).to eq('error')
        expect(adapter.sarif_level('HIGH')).to eq('error')
        expect(adapter.sarif_level('MODERATE')).to eq('warning')
        expect(adapter.sarif_level('LOW')).to eq('note')
      end
    end
  end

  describe '#sarif_report' do
    let(:scanner) { Salus::Scanners::NPMAudit.new(repository: repo, config: {}) }

    context 'npm file with errors' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/failure') }
      it 'should generate error in report' do
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['results'].length).to eq(2)
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(false)
      end
    end

    context 'npm file with no vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/success') }
      it 'should generate an empty sarif report' do
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]

        expect(report_object['results'].length).to eq(0)
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'npm project with vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/failure-2') }
      it 'should generate the right results and rules' do
        status = ProcessStatusDouble.new(1)
        stub_ret = Salus::ShellResult.new(stub_stdout_failure_2, stub_stderr_failure_2, status)
        allow(scanner).to receive(:run_shell).and_return(stub_ret)

        scanner.run

        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        results = JSON.parse(report.to_sarif)["runs"][0]["results"]
        result = results.first
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"]
        rule = rules.first

        # Check rule info
        expect(rule['id']).to eq("1005415")
        expect(rule['name']).to eq("Prototype Pollution in merge")
        expected = "All versions of package merge <2.1.1 are vulnerable to Prototype " \
                   "Pollution via _recursiveMerge ."
        expect(rule['fullDescription']['text']).to include(expected)
        expect(rule['helpUri']).to eq("https://github.com/advisories/GHSA-7wpw-2hjm-89gp")

        # Check result info
        expect(result['ruleId']).to eq("1005415")
        expect(result['level']).to eq('error')
      end
    end

    context 'npm project with exceptions' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/success_with_exceptions') }
      it 'does not contain excluded cves' do
        config_file = YAML.load_file(
          "spec/fixtures/npm_audit/success_with_exceptions/salus.yaml"
        )
        scanner = Salus::Scanners::NPMAudit.new(
          repository: repo, config: config_file['scanner_configs']['NPMAudit']
        )
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['results'].length).to eq(0)
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end
  end

  describe '#to_sarif' do
    let(:scanner) { Salus::Scanners::NPMAudit.new(repository: repo, config: {}) }
    context 'Should generate report when parse error is generated' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/failure-3') }
      it 'should be parsed once' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: true)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        uri = "https://docs.npmjs.com/cli/v7/commands/npm-audit"
        expect(report_object['tool']['driver']['informationUri']).to eq(uri)
      end
    end
  end
end
