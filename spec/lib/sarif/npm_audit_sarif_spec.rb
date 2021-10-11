require_relative '../../spec_helper'
require 'json'

describe Sarif::NPMAuditSarif do
  let(:vuln_1) { 1_004_707 } # was 39

  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::NPMAudit.new(repository: repo, config: {}) }

    before { scanner.run }

    context 'scan report with logged vulnerabilites' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/failure-2') }
      it 'parses information correctly' do
        issues = scanner.report.to_h[:info][:stdout][:advisories].values
        issue = issues.select { |i| i[:id] == vuln_1 }.first
        npm_sarif = Sarif::NPMAuditSarif.new(scanner.report, './')

        expect(npm_sarif.parse_issue(issue)).to include(
          id: vuln_1.to_s,
          name: "Incorrect Handling of Non-Boolean Comparisons During Minification in uglify-js",
          level: "CRITICAL",
          details: "Versions of `uglify-js` prior to 2.4.24 are affected by a "\
          "vulnerability which may cause crafted JavaScript to have altered functionality "\
          "after minification.\n\n\n\n\n## Recommendation\n\nUpgrade UglifyJS "\
          "to version >= 2.4.24.",
          messageStrings: { "cwe": { "text": "CWE-1254" },
                            "package": { "text": "uglify-js" },
                            "patched_versions": { "text": ">=2.4.24" },
                            "recommendation": { "text": "Upgrade to version 2.4.24 or later" },
                            "severity": { "text": "critical" },
                            "vulnerable_versions": { "text": "<2.4.24" } },
          help_url: "https://github.com/advisories/GHSA-34r7-q49f-h37c",
          uri: "package-lock.json",
          properties: { severity: "critical" },
          suppressed: false
        )
      end
    end

    context 'Duplicate advisories' do
      let(:path) { 'spec/fixtures/npm_audit/failure-2' }
      let(:repo) { Salus::Repo.new(path) }
      it 'should be parsed once' do
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
    before { scanner.run }

    context 'npm file with errors' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/failure') }
      it 'should generate error in report' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(false)
      end
    end

    context 'npm file with no vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/success') }
      it 'should generate an empty sarif report' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]

        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'npm project with vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/failure-2') }
      it 'should generate the right results and rules' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        results = JSON.parse(report.to_sarif)["runs"][0]["results"]
        result = results.select { |r| r['ruleId'] == vuln_1.to_s }.first
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"]
        rule = rules.select { |r| r['id'] == vuln_1.to_s }.first
        # Check rule info
        expect(rule['id']).to eq(vuln_1.to_s)
        expect(rule['name']).to eq("Incorrect Handling of Non-Boolean "\
          "Comparisons During Minification in uglify-js")
        expected = "Versions of `uglify-js` prior to 2.4.24 are"\
        " affected by a vulnerability which may cause crafted JavaScript to have altered"\
        " functionality after minification.\n\n\n\n\n## Recommendation\n\n"\
        "Upgrade UglifyJS to version >= 2.4.24."
        expect(rule['fullDescription']['text']).to eq(expected)
        expect(rule['helpUri']).to eq("https://github.com/advisories/GHSA-34r7-q49f-h37c")

        # Check result info
        expect(result['ruleId']).to eq(vuln_1.to_s)
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
