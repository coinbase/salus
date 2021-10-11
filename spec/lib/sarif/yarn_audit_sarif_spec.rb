require_relative '../../spec_helper'
require 'json'

describe Sarif::YarnAuditSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::YarnAudit.new(repository: repo, config: {}) }
    let(:error_id_fail_2) { "1002899" } # was 39 before the great yarn advisory reshuffling of '21
    before { scanner.run }

    context 'scan report with logged vulnerabilites' do
      let(:path) { 'spec/fixtures/yarn_audit/failure-2' }
      let(:repo) { Salus::Repo.new(path) }
      it 'parses information correctly' do
        issue = JSON.parse(scanner.report.to_h[:info][:stdout])[0]
        yarn_sarif = Sarif::YarnAuditSarif.new(scanner.report, path)

        expect(yarn_sarif.parse_issue(issue)).to include(
          id: error_id_fail_2,
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
          help_url: "https://www.npmjs.com/advisories/#{error_id_fail_2}",
          properties: { severity: "high" }
        )
      end
    end
  end

  describe '#sarif_report' do
    let(:scanner) { Salus::Scanners::YarnAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'Yarn file with errors' do
      let(:path) { 'spec/fixtures/yarn_audit/failure-3' }
      let(:repo) { Salus::Repo.new(path) }
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
      let(:error_id_fail_4) { "1004708" } # was 39 before the great yarn advisory reshuffling of '21

      it 'should generate the right results and rules' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)

        parsed_json = JSON.parse(report.to_sarif)
        result = parsed_json["runs"][0]["results"].select do |rule|
          rule["ruleId"] == error_id_fail_4
        end.first
        rule = parsed_json["runs"][0]["tool"]["driver"]["rules"].select do |r|
          r['id'] == error_id_fail_4
        end.first

        # Check rule info
        expect(rule['id']).to eq(error_id_fail_4)
        expect(rule['name']).to eq("Regular Expression Denial of Service in uglify-js")
        expect(rule['fullDescription']['text']).to eq("Regular Expression Denial "\
          "of Service in uglify-js")
        expect(rule['helpUri']).to eq("https://www.npmjs.com/advisories/#{error_id_fail_4}")

        # Check result info
        expect(result['ruleId']).to eq(error_id_fail_4)
        expect(result['ruleIndex']).to be >= 0 # liberal here to avoid hard coding the index
        expect(result['level']).to eq('error')
      end
    end

    context 'yarn.lock file with vulnerabilities having the same ID' do
      let(:path) { 'spec/fixtures/yarn_audit/failure-2' }
      let(:repo) { Salus::Repo.new(path) }
      it 'should generate all identified vulnerabilities' do
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
end
