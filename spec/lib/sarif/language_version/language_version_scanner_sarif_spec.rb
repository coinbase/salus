RSpec.shared_examples_for "language version scanner sarif" do |scanner_class,
                                                               scanner_name,
                                                               valid_version_repo_path,
                                                               invalid_version_repo_path,
                                                               error_msg|
  describe '#build_runs_object' do
    let(:config_file) { YAML.load_file(invalid_version_repo_path + '/salus.yml') }
    let(:scanner) do
      scanner_class.new(repository: repo,
                    config: config_file['scanner_configs'][scanner_name.to_s])
    end
    before { scanner.run }

    context 'version mismatch found in project' do
      let(:path) { invalid_version_repo_path }
      let(:repo) { Salus::Repo.new(path) }

      it 'creates valid sarif report with results populated' do
        adapter = described_class.new(scanner.report, path)
        report = adapter.build_runs_object(true)
        rules = report['tool'][:driver]['rules']
        results = report['results']

        expect(results.size).to eq(1)
        expect(results).to include(
          {
            "ruleId": Sarif::LanguageVersion::BaseSarif::LANGUAGE_VERSION_MISMATCH,
            "ruleIndex": 0,
            "level": "error",
            "message": {
              "text": error_msg
            },
            "properties": { "severity": Sarif::LanguageVersion::BaseSarif::SEVERITY },
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

        doc = Sarif::LanguageVersion::BaseSarif::LANGUAGE_VERSION_DOC_URI
        expect(rules[0]).to include(
          {
            "id": Sarif::LanguageVersion::BaseSarif::LANGUAGE_VERSION_MISMATCH,
            "name": scanner_name,
            "fullDescription": {
              "text": error_msg
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
        scan_reports = [
          [scanner.report, false]
        ]
        sarif_json = Sarif::SarifReport.new(scan_reports).to_sarif
        filtered_sarif = report.apply_report_sarif_filters(sarif_json)
        expect { Sarif::SarifReport.validate_sarif(filtered_sarif) }.not_to raise_error
      end
    end

    context 'no vulnerabilites found in project' do
      let(:config_path) { valid_version_repo_path + '/salus.yml' }
      let(:config_file) { YAML.load_file(config_path) }
      let(:path) { valid_version_repo_path }
      let(:repo) { Salus::Repo.new(path) }

      it 'does not find any version mismatch for valid repository' do
        adapter = described_class.new(scanner.report, path)
        report = adapter.build_runs_object(true)
        rules = report['tool'][:driver]['rules']
        results = report['results']

        expect(results).to be_empty
        expect(rules).to be_empty
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
