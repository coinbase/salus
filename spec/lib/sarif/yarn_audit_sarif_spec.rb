require_relative '../../spec_helper.rb'
require 'json'

describe Sarif::YarnAuditSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::YarnAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'scan report with logged vulnerabilites' do
      let(:repo) { Salus::Repo.new('spec/fixtures/yarn_audit/failure-2') }
      it 'parses information correctly' do
        issue = JSON.parse(scanner.report.to_h[:info][:stdout])[0]
        yarn_sarif = Sarif::YarnAuditSarif.new(scanner.report)

        expect(yarn_sarif.parse_issue(issue)).to include(
          id: "39",
          name: "Incorrect Handling of Non-Boolean Comparisons During Minification",
          level: "LOW",
          details: "Title: Incorrect Handling of Non-Boolean Comparisons During Minification\n"\
          "Package: uglify-js\nPatched in: >= 2.4.24\nDependency of:uglify-js \nSeverity: low",
          uri: "yarn.lock",
          help_url: "https://www.npmjs.com/advisories/39"
        )
      end
    end
  end

  describe '#sarif_report' do
    let(:scanner) { Salus::Scanners::YarnAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'Yarn file with errors' do
      let(:repo) { Salus::Repo.new('spec/fixtures/yarn_audit/failure-3') }
      it 'should generate error in report' do
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
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]

        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'yarn project with vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/yarn_audit/failure-4') }
      it 'should generate the right results and rules' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        result = JSON.parse(report.to_sarif)["runs"][0]["results"][0]
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"]
        # Check rule info
        expect(rules[0]['id']).to eq('39')
        expect(rules[0]['name']).to eq("Incorrect Handling of Non-Boolean Comparisons During"\
          " Minification")
        expect(rules[0]['fullDescription']['text']).to eq("Incorrect Handling of Non-Boolean"\
          " Comparisons During Minification")
        expect(rules[0]['helpUri']).to eq("https://www.npmjs.com/advisories/39")

        # Check result info
        expect(result['ruleId']).to eq('39')
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('note')
      end
    end

    context 'yarn.lock file with vulnerabilities having the same ID' do
      let(:repo) { Salus::Repo.new('spec/fixtures/yarn_audit/failure-2') }
      it 'should generate all identified vulnerabilities' do
        issue = JSON.parse(scanner.report.to_h[:info][:stdout])[0]
        yarn_sarif = Sarif::YarnAuditSarif.new(scanner.report)

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
end
