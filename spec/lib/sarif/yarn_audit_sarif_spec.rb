require_relative '../../spec_helper.rb'
require 'json'

describe Sarif::YarnAuditSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::YarnAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'scan report with logged vulnerabilites' do
      let(:repo) { Salus::Repo.new('spec/fixtures/yarn_audit/failure-2') }
      it 'parses information correctly' do
        issue = scanner.report.to_h.fetch(:logs).dump.split("\\n\\n")[0]
        yarn_sarif = Sarif::YarnAuditSarif.new(scanner.report)

        expect(yarn_sarif.parse_issue(issue)).to include(
          id: "YARN0039",
          name: "Incorrect Handling of Non-Boolean Comparisons During Minification",
          level: "LOW",
          details: "Package: uglify-js\nUpgrade to: >= 2.4.24\nDependency of:uglify-js",
          help_url: "https://www.npmjs.com/advisories/39",
          uri: "Yarn.lock"
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
        expect(message['text']).to include("Received malformed response from registry for"\
          " \"classnames-repo-does-not-exist\".")
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

    context 'go project with vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/yarn_audit/failure-4') }
      it 'should generate the right results and rules' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        result = JSON.parse(report.to_sarif)["runs"][0]["results"][0]
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"]
        # Check rule info
        expect(rules[0]['id']).to eq('YARN0039')
        expect(rules[0]['name']).to eq("Incorrect Handling of Non-Boolean Comparisons During"\
          " Minification")
        expect(rules[0]['fullDescription']['text']).to eq("Package: uglify-js\nUpgrade to:"\
          " >= 2.4.24\nDependency of:uglify-js")
        expect(rules[0]['helpUri']).to eq("https://www.npmjs.com/advisories/39")

        # Check result info
        expect(result['ruleId']).to eq('YARN0039')
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('warning')
      end
    end
  end
end
