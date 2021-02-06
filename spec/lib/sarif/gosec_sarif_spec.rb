require_relative '../../spec_helper.rb'
require 'json'
require 'json-schema'

describe Sarif::GosecSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::Gosec.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'scan report with logged vulnerabilites' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/vulnerable_goapp') }
      it 'parses information correctly' do
        gosec_sarif = Sarif::GosecSarif.new(scanner.report)
        issue = JSON.parse(scanner.log(''))['Issues'][0]

        # should Parse and fill out hash
        expected = "7: func test2() {\n8: \tpassword := \"hhend77dyyydbh&^psNSSZ)JSM--_%\"\n9: "\
        "\tfmt.Println(\"hello, from the vulnerable app\" + password)\n"
        expect(gosec_sarif.parse_issue(issue)).to include(
          id: "G101",
          name: "CWE-798",
          level: "HIGH",
          details: "Potential hardcoded credentials",
          start_line: 8,
          start_column: 2,
          help_url: "https://cwe.mitre.org/data/definitions/798.html",
          code: expected
        )
      end
    end
  end

  describe '#sarif_report' do
    let(:scanner) { Salus::Scanners::Gosec.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'non go project' do
      let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }
      it 'should handle generated error' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(false)

        message = report_object['invocations'][0]['toolExecutionNotifications'][0]['message']
        expect(message['text']).to include('0 lines of code were scanned')
      end
    end

    context 'go project with no vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/safe_goapp') }
      it 'should generate an empty sarif report' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]

        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'go project with vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/recursive_vulnerable_goapp') }

      it 'should generate the right results and rules' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        result = JSON.parse(report.to_sarif)["runs"][0]["results"][0]
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"]
        # Check rule info
        expect(rules[0]['id']).to eq('G101')
        expect(rules[0]['name']).to eq('CWE-798')
        expect(rules[0]['fullDescription']['text']).to eq('Potential hardcoded credentials')
        expect(rules[0]['helpUri']).to eq('https://cwe.mitre.org/data/definitions/798.html')

        # Check result info
        expect(result['ruleId']).to eq('G101')
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('error')
        expect(result['locations'][0]['physicalLocation']['region']['startLine']).to eq(8)
        expected = "7: func main() {\n8: \tpassword := \"hhend77dyyydbh&^psNSSZ)JSM--_%\"\n9: "\
        "\tfmt.Println(\"hello, from the vulnerable app\" + password)\n"
        snippet = result['locations'][0]['physicalLocation']['region']['snippet']['text'].to_s
        expect(snippet).to eq(expected)
      end
    end
  end
end
