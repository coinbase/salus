require_relative '../../spec_helper'

describe Sarif::RepoNotEmptySarif do
  describe '#build_runs_object' do
    let(:scanner) { Salus::Scanners::RepoNotEmpty.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'vulnerabilites found in project' do
      let(:repo) { Salus::Repo.new('spec/fixtures/repo_not_empty/blank') }
      it 'creates valid sarif report with results populated' do
        adapter = Sarif::RepoNotEmptySarif.new(scanner.report)
        report = adapter.build_runs_object(true)
        rules = report['tool'][:driver]['rules']
        results = report['results']

        expect(results.size).to eq(1)
        expect(results).to include(
          {
            "ruleId": "RNE0001",
            "ruleIndex": 0,
            "level": "error",
            "message": {
              "text": "Salus was run on a blank directory. This may indicate "\
               "misconfiguration such as not correctly voluming in the repository to be scanned."
            },
            "locations": [
              {
                "physicalLocation": {
                  "artifactLocation": {
                    "uri": "",
                    "uriBaseId": "%SRCROOT%"
                  }
                }
              }
            ]
          }
        )
        doc = "https://github.com/coinbase/salus/blob/master/docs/scanners/repository_not_blank.md"
        expect(rules[0]).to include(
          {
            "id": "RNE0001",
            "name": "RepositoryIsEmpty",
            "fullDescription": {
              "text": "Salus was run on a blank directory. This may indicate "\
              "misconfiguration such as not correctly voluming in the repository to be scanned."
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

      it 'creates a sarif report that follows the schema' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        expect { report.to_sarif }.not_to raise_error
      end
    end

    context 'no vulnerabilites found in project' do
      let(:repo) { Salus::Repo.new('spec/fixtures/repo_not_empty/non_blank') }
      it 'does not create sarif report for non-empty repo' do
        adapter = Sarif::RepoNotEmptySarif.new(scanner.report)
        report = adapter.build_runs_object(true)
        rules = report['tool'][:driver]['rules']
        results = report['results']

        expect(results.size).to eq(0)
        expect(rules.size).to eq(0)
      end
    end
  end
end
