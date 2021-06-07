require_relative '../../spec_helper.rb'
require 'json'

describe Sarif::NPMAuditSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::NPMAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'scan report with logged vulnerabilites' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/failure-2') }
      it 'parses information correctly' do
        issue = scanner.report.to_h[:info][:stdout][:advisories].values[0]
        npm_sarif = Sarif::NPMAuditSarif.new(scanner.report)

        expect(npm_sarif.parse_issue(issue)).to include(
          id: "39",
          name: "Incorrect Handling of Non-Boolean Comparisons During Minification",
          level: "LOW",
          details: "Versions of `uglify-js` prior to 2.4.24 are"\
          " affected by a vulnerability which may cause crafted JavaScript to have altered"\
          " functionality after minification.\n\n",
          messageStrings: {"package": {"text": "uglify-js"},
                           "severity": {"text": "low"},
                           "patched_versions": {"text": ">= 2.4.24"},
                           "cwe": {"text": "CWE-95"},
                           "recommendation": {"text": "Upgrade UglifyJS to version >= 2.4.24."},
                           "vulnerable_versions": {"text": "<= 2.4.23"}},
          help_url: "https://npmjs.com/advisories/39",
          uri: "package-lock.json"
        )
      end
    end

    context 'Duplicate advisories' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/failure-2') }
      it 'should be parsed once' do
        issue = scanner.report.to_h[:info][:stdout][:advisories].values[0]

        npm_sarif = Sarif::NPMAuditSarif.new(scanner.report)
        expect(npm_sarif.parse_issue(issue).empty?).to eq(false)
        expect(npm_sarif.parse_issue(issue)).to eq(nil)
      end
    end
  end

  describe '#sarif_level' do
    let(:scanner) { Salus::Scanners::NPMAudit.new(repository: repo, config: {}) }
    before { scanner.run }
    context 'NPM severities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/npm_audit/success') }
      it 'should be mapped to the right sarif levels' do
        # NPM Severities: https://docs.npmjs.com/about-audit-reports#severity
        adapter = Sarif::NPMAuditSarif.new(scanner.report)

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
        result = JSON.parse(report.to_sarif)["runs"][0]["results"][0]
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"]
        # Check rule info
        expect(rules[0]['id']).to eq('39')
        expect(rules[0]['name']).to eq("Incorrect Handling of Non-Boolean Comparisons During"\
          " Minification")
        expected = "Versions of `uglify-js` prior to 2.4.24 are"\
        " affected by a vulnerability which may cause crafted JavaScript to have altered"\
        " functionality after minification.\n\n"
        expect(rules[0]['fullDescription']['text']).to eq(expected)
        expect(rules[0]['helpUri']).to eq("https://npmjs.com/advisories/39")

        # Check result info
        expect(result['ruleId']).to eq('39')
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('note')
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
