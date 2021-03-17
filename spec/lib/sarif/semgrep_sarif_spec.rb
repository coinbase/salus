require_relative '../../spec_helper.rb'
require 'json'

describe Sarif::SemgrepSarif do
  context '#sarif_level' do
    it 'maps severity levels correctly' do
      config = {
        "matches" => [
          {
            "pattern" => "$X == $X",
            "language" => "python",
            "message" => "Useless equality test.",
            "required" => true
          }
        ]
      }
      repo = Salus::Repo.new("spec/fixtures/semgrep")
      scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
      scanner.run
      adapter = Sarif::SemgrepSarif.new(scanner.report)
      expect(adapter.sarif_level('HIGH')).to eq('error')
      expect(adapter.sarif_level('MEDIUM')).to eq('error')
      expect(adapter.sarif_level('LOW')).to eq('warning')
      expect(adapter.sarif_level('warn')).to eq('warning')
      expect(adapter.sarif_level('warning')).to eq('warning')
    end
  end

  describe '#to_sarif' do
    context 'generates a valid sarif report' do
      it '' do
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        config = {
          "matches" => [
            {
              "pattern" => "$X == $X",
              "language" => "python",
              "message" => "Useless equality test.",
              "required" => true
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)

        sarif_report = JSON.parse(report.to_sarif)
        result = sarif_report["runs"][0]["results"][0]
        rules = sarif_report["runs"][0]["tool"]["driver"]["rules"]
        runs_obj = sarif_report["runs"][0]
        expect(rules[0]['id']).to eq("$X == $X")
        expect(rules[0]['name']).to eq("$X == $X / Useless equality test.")
        expect(runs_obj['invocations'][0]['executionSuccessful']).to eq(true)
        expect(result['ruleId']).to eq("$X == $X")
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('error')
        expect(result['locations'][0]['physicalLocation']['region']['startLine']).to eq(10)
      end
    end
  end
end
