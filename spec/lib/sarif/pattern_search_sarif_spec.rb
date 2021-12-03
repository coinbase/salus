require_relative '../../spec_helper'

describe Sarif::PatternSearchSarif do
  context '#parse_issue' do
    let(:path) { 'spec/fixtures/pattern_search' }
    it 'doesnt add duplicates to the report' do
      repo = Salus::Repo.new(path)
      config = {
        'matches' => [
          { 'regex' => 'Nerv', 'required' => true, 'message' => 'important string' }
        ]
      }
      scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
      scanner.run
      adapter = Sarif::PatternSearchSarif.new(scanner.report, path)
      x = scanner.report.to_h.dig(:info, :hits)
      adapter.parse_issue(x[0])
      expect(adapter.parse_issue(x[0])).to eq(nil)
    end
  end

  describe '#build_runs_object' do
    context 'vulnerabilites found in project' do
      let(:path) { 'spec/fixtures/pattern_search' }
      it 'creates valid sarif report with results populated' do
        repo = Salus::Repo.new(path)
        config = {
          'matches' => [
            { 'regex' => 'Nerv', 'forbidden' => true, 'message' => 'not important string' },
            { 'regex' => 'Nerv Cell', 'required' => true, 'message' => 'important string' }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: true)

        adapter = Sarif::PatternSearchSarif.new(scanner.report, path)
        report = adapter.build_runs_object(true)
        rules = report['tool'][:driver]['rules']
        results = report['results']
        expect(results).to include(
          {
            "ruleId": "Forbidden Pattern Found",
            "ruleIndex": 0,
            "level": "error",
            "message": {
              "text": "not important string. Pattern Nerv is forbidden."
            },
            "properties": { severity: "HIGH" },
            "locations": [
              {
                "physicalLocation": {
                  "artifactLocation": {
                    "uri": "lance.txt",
                    "uriBaseId": "%SRCROOT%"
                  },
                  "region": {
                    "startLine": 3,
                    "startColumn": 1,
                    "snippet": {
                      "text": "lance.txt:3:Nerv housed the lance."
                    }
                  }
                }
              }
            ]
          }
        )
        doc = "https://github.com/coinbase/salus/blob/master/docs/scanners/pattern_search.md"
        expect(rules).to include(
          {
            "id": "Forbidden Pattern Found",
            "name": "Forbidden Pattern Found",
            "fullDescription": {
              "text": "not important string. Pattern Nerv is forbidden."
            },
            "messageStrings": {},
            "helpUri": doc,
            "help": {
              "text": "More info: #{doc}",
              "markdown": "[More info](#{doc})."
            }
          }
        )
      end
    end
  end

  describe 'sarif diff' do
    context 'git diff support' do
      it 'should find code in git diff' do
        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_6.txt'
        snippet = "hello.py:4:  foo()"
        git_diff = File.read(git_diff_file)
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::PatternSearchSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true

        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_5.txt'
        snippet = "hello.py:4:  foo()"
        git_diff = File.read(git_diff_file)
        new_lines_in_git_diff = Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
        r = Sarif::PatternSearchSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be false
      end
    end
  end
end
