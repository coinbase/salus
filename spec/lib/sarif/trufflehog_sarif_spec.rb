require_relative '../../spec_helper.rb'

describe Sarif::TrufflehogSarif do
  describe '#to_sarif' do
    let(:path) { 'spec/fixtures/secrets' }
    let(:repo) { Salus::Repo.new(path) }

    context 'generates correct sarif' do
      it 'contains vulnerabilities found in report' do
        config = { 'only-verified' => false }
        scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: config)
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: true)
        sarif_report = JSON.parse(report.to_sarif)
        result = sarif_report["runs"][0]["results"]

        expected_vul0 = { "level" => "error",
                          "locations" => [{ "physicalLocation" => {
                            "artifactLocation" => { "uri" => "logins.txt",
                                                    "uriBaseId" => "%SRCROOT%" },
                                              "region" => { "snippet" => { "text" =>
                                                            "2d00fc02b2d554da2a58feb7bac"\
                                                            "53673126f5c10f7c0a718e49e63"\
                                                            "5c489bf505" },
                                                            "startColumn" => 1, "startLine" => 2 }
                          } }],
                          "message" => { "text" => "Leaked credential detected" },
                          "properties" => { "severity" => "high" },
                          "ruleId" => "FlatIO-PLAIN", "ruleIndex" => 1 }
        expected_vul1 = { "level" => "error",
                          "locations" => [{ "physicalLocation" => {
                            "artifactLocation" => { "uri" => "url.txt",
                                                    "uriBaseId" => "%SRCROOT%" },
                            "region" => { "snippet" => { "text" =>
                                                         "8f839fbea674797911361d91124"\
                                                         "50478e280b982321c22363ca7a7"\
                                                         "4f36a4bbd6" },
                                          "startColumn" => 1, "startLine" => 2 }
                          } }],
                          "message" => { "text" => "Leaked credential detected" },
                          "properties" => { "severity" => "high" },
                          "ruleId" => "JDBC-PLAIN", "ruleIndex" => 0 }
        expected_vul2 = { "level" => "error",
                          "locations" => [{ "physicalLocation" => {
                            "artifactLocation" => { "uri" => "url.txt",
                                                    "uriBaseId" => "%SRCROOT%" },
                            "region" => { "snippet" => { "text" =>
                                                         "e364ca3424d2454bc630a574e16"\
                                                         "9102b6d6be06189a2038badb969"\
                                                         "cf47755abe" },
                                          "startColumn" => 1, "startLine" => 1 }
                          } }],
                          "message" => { "text" => "Leaked credential detected" },
                          "properties" => { "severity" => "high" },
                          "ruleId" => "JDBC-PLAIN", "ruleIndex" => 0 }
        expect(result.size).to eq(3)
        [expected_vul0, expected_vul1, expected_vul2].each { |v| expect(result).to include(v) }
      end

      it 'sarif has no vulnerabilities in results if exectuion successful' do
        scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})
        scanner.run
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: true)
        sarif_report = JSON.parse(report.to_sarif)
        result = sarif_report["runs"][0]["results"]
        expect(result).to be_empty
      end
    end
  end
end
