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
          id: "NPM0039",
          name: "Incorrect Handling of Non-Boolean Comparisons During Minification",
          level: "LOW",
          details: "Package:uglify-js \nDescription:Versions of `uglify-js` prior to 2.4.24 are"\
          " affected by a vulnerability which may cause crafted JavaScript to have altered"\
          " functionality after minification.\n\n \nRecommendation: Upgrade UglifyJS to version"\
          " >= 2.4.24.\nVulnerable Versions: <= 2.4.23 \nSeverity:low \nPatched Versions:"\
          " >= 2.4.24\nCWE: CWE-95 ",
          help_url: "https://npmjs.com/advisories/39",
          uri: "package-lock.json"
        )
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
        expect(rules[0]['id']).to eq('NPM0039')
        expect(rules[0]['name']).to eq("Incorrect Handling of Non-Boolean Comparisons During"\
          " Minification")
        expected = "Package:uglify-js \nDescription:Versions of `uglify-js` prior to 2.4.24 are"\
        " affected by a vulnerability which may cause crafted JavaScript to have altered"\
        " functionality after minification.\n\n \nRecommendation: Upgrade UglifyJS to version"\
        " >= 2.4.24.\nVulnerable Versions: <= 2.4.23 \nSeverity:low \nPatched Versions: >= 2.4.24"\
        "\nCWE: CWE-95 "
        expect(rules[0]['fullDescription']['text']).to eq(expected)
        expect(rules[0]['helpUri']).to eq("https://npmjs.com/advisories/39")

        # Check result info
        expect(result['ruleId']).to eq('NPM0039')
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('note')
      end
    end
  end
end
