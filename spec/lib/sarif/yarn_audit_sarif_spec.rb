require_relative '../../spec_helper.rb'
require 'json'

describe Sarif::YarnAuditSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::YarnAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'scan report with logged vulnerabilites' do
      let(:repo) { Salus::Repo.new('spec/fixtures/yarn_audit/failure-2') }
      it 'parses information correctly' do
        issue = scanner.report.to_h.fetch(:logs).split("\n\n")[0]
        yarn_sarif = Sarif::YarnAuditSarif.new(scanner.report)

        expect(yarn_sarif.parse_issue(issue)).to include(
          id: "39",
          name: "Incorrect Handling of Non-Boolean Comparisons During Minification",
          level: "LOW",
          details: "Title: Incorrect Handling of Non-Boolean Comparisons During Minification\n"\
          "Package: uglify-js\nPatched in: >= 2.4.24\nDependency of:uglify-js \nSeverity: low",
          help_url: "https://www.npmjs.com/advisories/39",
          uri: "yarn.lock"
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
        expect(message['text']).to include("SALUS ERRORS")
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
      let(:repo) { Salus::Repo.new('spec/fixtures/yarn_audit/failure-4') }
      it 'should generate all identified vulnerabilities' do
        scan_report = Salus::ScanReport.new("YarnAudit")
        scan_report.log(
          "Package: ini\nPatched in: >1.3.6\nDependency of: firebase\n"\
          "More info: https://www.npmjs.com/advisories/1523\nSeverity: low"\
          "\nTitle: Prototype Pollution\nID: 1589\n\n"\
          "Package: ini\nPatched in: >1.3.6\nDependency of: react-scripts\n"\
          "More info: https://www.npmjs.com/advisories/1523\nSeverity: low"\
          "\nTitle: Prototype Pollution\nID: 1589\n\n"
        )
        scan_report.add_version('5.0')
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scan_report, required: false)
        result = JSON.parse(report.to_sarif)["runs"][0]["results"]
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"]
        expect(rules.size).to eq(1)
        expect(result.size).to eq(2)

        description1 = result[0]["message"]["text"]
        description2 = result[1]["message"]["text"]
        expect(description1).to eq("Title: Prototype Pollution\nPackage: ini\nPatched in: >1.3.6"\
          "\nDependency of:firebase \nSeverity: low")
        expect(description2).to eq("Title: Prototype Pollution\nPackage: ini\nPatched in: >1.3.6"\
          "\nDependency of:react-scripts \nSeverity: low")
      end
    end
  end

  describe '#sarif_level' do
    it 'maps severities to the right sarif level' do
      adapter = Sarif::YarnAuditSarif.new([])
      expect(adapter.sarif_level("INFO")).to eq("note")
      expect(adapter.sarif_level("LOW")).to eq("note")
      expect(adapter.sarif_level("MODERATE")).to eq("warning")
      expect(adapter.sarif_level("HIGH")).to eq("error")
      expect(adapter.sarif_level("CRITICAL")).to eq("error")
    end
  end
end
