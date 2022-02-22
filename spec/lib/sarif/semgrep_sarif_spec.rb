require_relative '../../spec_helper'
require 'json'

describe Sarif::SemgrepSarif do
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
              "forbidden" => true
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: true)
        sarif_report = JSON.parse(report.to_sarif)
        result = sarif_report["runs"][0]["results"]

        expect(result).to include({
          "ruleId": "Forbidden Pattern Found",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "Useless equality test.. Pattern $X == $X is forbidden."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "examples/trivial2.py",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 10,
                  "startColumn": 1,
                  "snippet": {
                    "text": "    if user.id == user.id"
                  }
                }
              }
            }
          ],
          "properties": { "severity": "HIGH" }
        }.deep_stringify_keys)
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

        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: true)
        sarif_report = JSON.parse(report.to_sarif)
        result = sarif_report["runs"][0]["results"][0]
        rules = sarif_report["runs"][0]["tool"]["driver"]["rules"]
        semgrep_doc_url = Sarif::SemgrepSarif::SEMGREP_URI
        expect(rules).to include(
          {
            "id" => "Required Pattern Not Found",
            "name" => "Required Pattern Not Found",
            "fullDescription" => {
              "text" => "Required Pattern Not Found"
            },
            "messageStrings" => {},
            "helpUri" => semgrep_doc_url,
            "help" => {
              "text" => "More info: #{semgrep_doc_url}",
              "markdown" => "[More info](#{semgrep_doc_url})."
            }
          }
        )
        expect(result).to include(
          {
            "ruleId" => "Required Pattern Not Found",
            "ruleIndex" => 1,
            "level" => "error",
            "message" => {
              "text" => "Useless equality test.. Pattern 1 == $X is required but not found."
            },
            "locations" => []
          }
        )
      end
    end
  end
end
