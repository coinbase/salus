require_relative '../../spec_helper'

describe Sarif::RepoNotEmptySarif do
  describe '#build_runs_object' do
    let(:scanner) { Salus::Scanners::RepoNotEmpty.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'vulnerabilites found in project' do
      let(:path) { 'spec/fixtures/repo_not_empty/blank' }
      let(:repo) { Salus::Repo.new(path) }
      it 'creates valid sarif report with results populated' do
        adapter = Sarif::RepoNotEmptySarif.new(scanner.report, path)
        report = adapter.build_runs_object(true)
        rules = report['tool'][:driver]['rules']
        results = report['results']

        expect(results.size).to eq(1)
        expect(results).to include(
          {
            "ruleId": "RNE0001",
            "ruleIndex": 0,
            "level": "note",
            "message": {
              "text": "Salus was run on a blank directory. This may indicate "\
               "misconfiguration such as not correctly voluming in the repository to be scanned."
            },
            "properties": { "severity": "VERY LOW" },
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
        report = Salus::Report.new(project_name: "Neon Genesis")
        scan_reports = [
          [scanner.report, false]
        ]
        sarif_json = Sarif::SarifReport.new(scan_reports).to_sarif
        filtered_sarif = report.apply_report_sarif_filters(sarif_json)
        expect { Sarif::SarifReport.validate_sarif(filtered_sarif) }.not_to raise_error
      end

      it 'creates a sarif report that follows the schema' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        scan_reports = [
          [scanner.report, false]
        ]
        sarif_json = Sarif::SarifReport.new(scan_reports).to_sarif
        filtered_sarif = report.apply_report_sarif_filters(sarif_json)
        expect { Sarif::SarifReport.validate_sarif(filtered_sarif) }.not_to raise_error
      end
    end

    context 'no vulnerabilites found in project' do
      let(:path) { 'spec/fixtures/repo_not_empty/non_blank' }
      let(:repo) { Salus::Repo.new(path) }
      it 'does not create sarif report for non-empty repo' do
        adapter = Sarif::RepoNotEmptySarif.new(scanner.report, path)
        report = adapter.build_runs_object(true)
        rules = report['tool'][:driver]['rules']
        results = report['results']

        expect(results.size).to eq(0)
        expect(rules.size).to eq(0)
        report = Salus::Report.new(project_name: "Neon Genesis")
        scan_reports = [
          [scanner.report, false]
        ]
        sarif_json = Sarif::SarifReport.new(scan_reports).to_sarif
        filtered_sarif = report.apply_report_sarif_filters(sarif_json)
        expect { Sarif::SarifReport.validate_sarif(filtered_sarif) }.not_to raise_error
      end
    end
  end
end
