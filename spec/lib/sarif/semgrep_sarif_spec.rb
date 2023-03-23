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
          "ruleId": "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
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
          "properties": { "severity": "ERROR" }
        }.deep_stringify_keys)

        expect(result).to include({
                                    "level" => "error",
          "locations" => [
            { "physicalLocation" => { "artifactLocation" =>
              { "uri" =>
               "/home/spec/fixtures/semgrep/invalid/unparsable_py.py",
               "uriBaseId" => "%SRCROOT%" }, "region" => {
                 "startColumn" => 1, "startLine" => 3
               } } }
          ],
          "message" => { "text" =>
                         "Syntax error at line "\
                         "/home/spec/fixtures/semgrep/invalid/unparsable_py.py:3:"\
                         "\n `print(\"foo\"` was unexpected" },
          "ruleId" => "SAL002", "ruleIndex" => 1
                                  })
      end

      it 'vulnerabilities found in report have user specified id' do
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        config = {
          "matches" => [
            {
              "config" => "semgrep-config.yml",
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
        # semgrep-eqeq-test is the user-specified id in the semgrep config
        matches = result.select { |r| r["ruleId"] == "semgrep-eqeq-test" }
        expect(matches.size).to eq(3)

        rules = sarif_report['runs'][0]['tool']['driver']['rules']

        # rubocop:disable Layout/LineLength
        expect(rules).to eq([{ "fullDescription" => { "text" => "errors reported by scanner" },
          "help" => { "markdown" => "[More info](https://github.com/coinbase/salus/blob/master/docs/scanners/semgrep.md).", "text" => "More info: https://github.com/coinbase/salus/blob/master/docs/scanners/semgrep.md" },
          "helpUri" => "https://github.com/coinbase/salus/blob/master/docs/scanners/semgrep.md",
          "id" => "SAL002",
          "messageStrings" => {},
          "name" => "Syntax error" },
                             { "fullDescription" => { "text" => "user.id == user.id is always true\n\trule_id: semgrep-eqeq-test. Pattern in semgrep-config.yml is forbidden." },
                              "help" => { "markdown" => "[More info](https://github.com/coinbase/salus/blob/master/docs/scanners/semgrep.md).", "text" => "More info: https://github.com/coinbase/salus/blob/master/docs/scanners/semgrep.md" },
                              "helpUri" => "https://github.com/coinbase/salus/blob/master/docs/scanners/semgrep.md",
                              "id" => "semgrep-eqeq-test",
                              "messageStrings" => { "cwe" => { "text" => "[\"CWE-676: Use of Potentially Dangerous Function\"]" },
                              "severity" => { "text" => "WARNING" } },
                              "name" => " / user.id == user.id is always true\n\trule_id: semgrep-eqeq-test Forbidden Pattern Found" }])
        # rubocop:enable Layout/LineLength
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

      it 'sarif contains correct code snippet' do
        config = {
          "matches" => [
            {
              "pattern" => "foo(...)",
              "language" => "ruby",
              "message" => "My msg",
              "forbidden" => true
            }
          ]
        }
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: true)
        sarif_report = JSON.parse(report.to_sarif)
        result_loc = sarif_report["runs"][0]["results"][0]["locations"][0]
        code_snippet = result_loc["physicalLocation"]["region"]["snippet"]["text"]
        expect(code_snippet).to eq("foo('a:b', 'a:b:c:d')")
      end
    end
  end

  describe 'sarif diff' do
    context 'git diff support' do
      let(:git_diff) { File.read('spec/fixtures/sarifs/diff/git_diff_9.txt') }

      it 'should find code in git diff if snippet' do
        snippet = "      bar()"
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::SemgrepSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true
      end

      it 'should find code in git diff if snippet has multiple lines' do
        snippet = "      if x ==\n         x"
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::SemgrepSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true
      end

      it 'should not find code in git diff if snippet not in git diff' do
        snippet = "hello_world()"
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::SemgrepSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be false
      end
    end
  end
end
