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
                                                            "216ce860c78081b83f255ca"\
                                                            "d4d032361677e4aea87dace"\
                                                            "cd387e62505e1e4a50dd947"\
                                                            "b3ce9166b70d8b9aaa45215"\
                                                            "c1b512c518b5384e5067ee7"\
                                                            "d29011da0efb4" },
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
                                                         "jdbc:postgresql://localhost:2345/"\
                                                         "test?user=test&password=DCBA&"\
                                                         "loggerLevel=DEBUG&&&"\
                                                         "loggerFile=./blah.jsp" },
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
                                                         "jdbc:postgresql://localhost:5432/"\
                                                         "test?user=test&password=ABCD&"\
                                                         "loggerLevel=DEBUG&&&"\
                                                         "loggerFile=./blah.jsp" },
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

  describe 'sarif diff' do
    context 'git diff support' do
      let(:new_lines_in_git_diff) do
        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_10.txt'
        git_diff = File.read(git_diff_file)
        Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
      end

      it 'should find code in git diff' do
        snippet = 'jdbc:postgresql://localhost:2345/test?user=test&'\
                  'password=DCBA&loggerLevel=DEBUG&&&loggerFile=./blah.jsp'
        r = Sarif::TrufflehogSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true
      end

      it 'should not find code in git diff if snippet not in git diff' do
        snippet = 'jdbc:postgresql://localhost:80/test?user=test&'\
                  'password=abcd&loggerLevel=DEBUG&&&loggerFile=./blah.jsp'
        r = Sarif::TrufflehogSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be false
      end
    end
  end
end
