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
      it 'contains vulnerabilities found in report' do
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
        report.add_scan_report(scanner.report, required: true)

        sarif_report = JSON.parse(report.to_sarif)
        result = sarif_report["runs"][0]["results"][0]
        expect(result).to include({ "ruleId" => "$X == $X",
          "ruleIndex" => 0,
          "level" => "error", "message" => {
            "text" => "Pattern: $X == $X\nMessage:Useless equality test.\n\nRequired:true"
          },
          "locations" => [{
            "physicalLocation" => {
              "artifactLocation" => {
                "uri" => "examples/trivial2.py",
                "uriBaseId" => "%SRCROOT%"
              },
              "region" => {
                "startLine" => 10,
                "startColumn" => 1,
                "snippet" => {
                  "text" => "    if user.id == user.id"
                }
              }
            }
          }] })
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

      it 'contains info about missing required vulnerabilities' do
        config = {
          "matches" => [
            {
              "pattern" => "1 == $X",
              "language" => "python",
              "message" => "Useless equality test.",
              "required" => true
            }
          ]
        }
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run
        # puts scanner.report.to_h
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        sarif_report = JSON.parse(report.to_sarif)
        result = sarif_report["runs"][0]["results"][1]
        rules = sarif_report["runs"][0]["tool"]["driver"]["rules"]
        expect(rules).to include(
          {
            "id" => "Required Pattern Not Found",
            "name" => "Required Pattern Not Found",
            "fullDescription" => {
              "text" => "Required Pattern Not Found"
            },
            "helpUri" => "https://semgrep.dev/docs/writing-rules/rule-syntax/",
            "help" => {
              "text" => "More info: https://semgrep.dev/docs/writing-rules/rule-syntax/",
              "markdown" => "[More info](https://semgrep.dev/docs/writing-rules/rule-syntax/)."
            }
          }
        )
        expect(result).to include(
          {
            "ruleId" => "Required Pattern Not Found",
            "ruleIndex" => 1,
            "level" => "error",
            "message" => {
              "text" => " pattern \"1 == $X\" was not found - Useless equality test."
            },
            "locations" => [
              {
                "physicalLocation" => {
                  "artifactLocation" => {
                    "uri" => "",
                    "uriBaseId" => "%SRCROOT%"
                  }
                }
              }
            ]
          }
        )
      end
    end
  end
end
