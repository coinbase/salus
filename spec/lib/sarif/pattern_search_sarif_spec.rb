require_relative '../../spec_helper.rb'
require 'json'

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
            { 'regex' => 'Nerv', 'required' => true, 'message' => 'important string' }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run
        adapter = Sarif::PatternSearchSarif.new(scanner.report)
        report = adapter.build_runs_object(true)
        rules = report['tool'][:driver]['rules']
        results = report['results']
        expect(results).to include(
          {
            ruleId: "Nerv",
            ruleIndex: 0,
            level: "error",
            message: {
              text: "Regex: Nerv\nForbidden: false\nMessage:important string\nRequired: true"
            },
            locations: [{
              physicalLocation: {
                artifactLocation: {
                  uri: "seal.txt",
                  uriBaseId: "%SRCROOT%"
                }, region: {
                  startLine: 3,
                  startColumn: 1,
                  snippet: {
                    text: "seal.txt:3:Nerv is tasked with taking over when the UN fails."
                  }
                }
              }
            }]
          }
        )
        doc = "https://github.com/coinbase/salus/blob/master/docs/scanners/pattern_search.md"
        expect(rules).to include(
          {
            id: "Nerv",
            name: "Regex: Nerv",
            fullDescription: {
              text: "Regex: Nerv\nForbidden: false\nMessage:important string\nRequired: true"
            },
            helpUri: doc,
            help: {
              text: "More info: #{doc}",
              markdown: "[More info](#{doc})."
            }
          }
        )
      end
    end
  end
end
