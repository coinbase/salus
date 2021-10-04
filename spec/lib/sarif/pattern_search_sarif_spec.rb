require_relative '../../spec_helper'

describe Sarif::PatternSearchSarif do
  context '#parse_issue' do
    it 'doesnt add duplicates to the report' do
      repo = Salus::Repo.new('spec/fixtures/pattern_search')
      config = {
        'matches' => [
          { 'regex' => 'Nerv', 'required' => true, 'message' => 'important string' }
        ]
      }
      scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
      scanner.run
      adapter = Sarif::PatternSearchSarif.new(scanner.report)
      x = scanner.report.to_h.dig(:info, :hits)
      adapter.parse_issue(x[0])
      expect(adapter.parse_issue(x[0])).to eq(nil)
    end
  end

  describe '#build_runs_object' do
    context 'vulnerabilites found in project' do
      it 'creates valid sarif report with results populated' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
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

        adapter = Sarif::PatternSearchSarif.new(scanner.report)
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
end
