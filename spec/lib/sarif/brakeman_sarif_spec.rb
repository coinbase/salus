require_relative '../../spec_helper.rb'
require 'json'

describe Sarif::BrakemanSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::Brakeman.new(repository: repo, config: { 'path' => path }) }
    before { scanner.run }

    context 'scan report with logged vulnerabilites' do
      let(:repo) { Salus::Repo.new('spec/fixtures') }
      let(:path) { '/home/spec/fixtures/brakeman/vulnerable_rails_app' }
      it 'parses information correctly' do
        brakeman_sarif = Sarif::BrakemanSarif.new(scanner.report)
        issue = JSON.parse(scanner.log(''))['warnings'][0]

        expect(brakeman_sarif.parse_issue(issue)).to include(
          id: "BRAKE0013",
          name: "Evaluation/Dangerous Eval",
          level: "HIGH",
          details: "User input in eval",
          start_line: 3,
          start_column: 1,
          help_url: "https://brakemanscanner.org/docs/warning_types/dangerous_eval/",
          code: "eval(params[:evil])",
          uri: "app/controllers/static_controller_controller.rb"
        )
      end
    end
  end

  describe '#sarif_report' do
    let(:scanner) { Salus::Scanners::Brakeman.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'non go project' do
      let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }
      it 'should handle generated error' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(false)

        message = report_object['invocations'][0]['toolExecutionNotifications'][0]['message']
        expect(message['text']).to include('brakeman exited with an unexpected exit status')
      end
    end

    context 'go project with no vulnerabilities' do
      let(:repo) { Salus::Repo.new('/home/spec/fixtures/brakeman/bundler_2') }
      it 'should generate an empty sarif report' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]

        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'go project with vulnerabilities' do
      let(:repo) { Salus::Repo.new('/home/spec/fixtures/brakeman/vulnerable_rails_app') }
      it 'should generate the right results and rules' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        result = JSON.parse(report.to_sarif)["runs"][0]["results"][0]
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"]
        # Check rule info
        expect(rules[0]['id']).to eq('BRAKE0013')
        expect(rules[0]['name']).to eq('Evaluation/Dangerous Eval')
        expect(rules[0]['fullDescription']['text']).to eq('User input in eval')
        expect(rules[0]['helpUri']).to eq('https://brakemanscanner.org/docs/warning_types'\
          '/dangerous_eval/')

        # Check result info
        expect(result['ruleId']).to eq('BRAKE0013')
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('error')
        expect(result['locations'][0]['physicalLocation']['region']['startLine']).to eq(3)
        snippet = result['locations'][0]['physicalLocation']['region']['snippet']['text'].to_s
        expect(snippet).to eq("eval(params[:evil])")
      end
    end
  end
end
