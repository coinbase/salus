require_relative '../../spec_helper.rb'

describe Sarif::GosecSarif do
  describe '#parse_issue' do
  end
  context 'with vulnerable solidity project' do
    let(:repo) { Salus::Repo.new('spec/fixtures/slither/solidity-bad2') }
    it 'should generate report with logged vulnerabilities' do
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      scanner.run
      report = Salus::Report.new(project_name: "Neon Genesis")
      report.add_scan_report(scanner.report, required: false)
      result = JSON.parse(report.to_sarif)['runs'][0]["results"][0]
      expect(result).to include(
        "level" => "error",
        "locations" => [
          { "physicalLocation" => {
            "artifactLocation" => {
              "uri" => "contracts/bad-contract1.sol#L4-L8",
               "uriBaseId" => "%SRCROOT%"
            },
              "region" => {
                "startColumn" => 1,
                "startLine" => 4
              }
          } }
        ],
          "message" => {
            "text" => "C.f() (bad-contract1.sol#4-8) contains an incorrect shift operation: "\
            "a = 8 >> a (bad-contract1.sol#6)\n"
          },
            "properties" => { "confidence" => "High" },
            "ruleId" => "incorrect-shift",
            "ruleIndex" => 0
      )
    end
  end

  context 'with non vulnerable solidity project' do
    let(:repo) { Salus::Repo.new('spec/fixtures/slither/solidity-bad3') }
    it 'should generate an empty sarif report' do
      config_file = "spec/fixtures/slither/solidity-bad3/salus_exclude_optimization.yaml"
      config = Salus::Config.new([File.read(config_file)]).scanner_configs['Slither']
      scanner = Salus::Scanners::Slither.new(repository: repo, config: config)
      scanner.run
      report = Salus::Report.new(project_name: "Spirited Away")
      report.add_scan_report(scanner.report, required: false)
      report_object = JSON.parse(report.to_sarif)['runs'][0]

      expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
    end
  end
end
