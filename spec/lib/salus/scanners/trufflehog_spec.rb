require_relative '../../../spec_helper.rb'

describe Salus::Scanners::Trufflehog do
  describe '#should_run?' do
    it 'should return true with empty directory' do
      repo = Salus::Repo.new('spec/fixtures/secrets/empty')
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  it 'should return true with non empty directory' do
    repo = Salus::Repo.new('spec/fixtures/secrets')
    scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})
    expect(scanner.should_run?).to eq(true)
  end

  describe '#run' do
    it 'should pass when there are no secrets' do
      repo = Salus::Repo.new('spec/fixtures/secrets/benign')
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})
      expect(scanner).not_to receive(:report_failure)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should pass when there are secrets and --only-verified is true' do
      # --only-verified is true by default
      repo = Salus::Repo.new('spec/fixtures/secrets')
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})
      expect(scanner).not_to receive(:report_failure)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(true)

      # explicitly setting --only-verified=true should yield the same behavior
      config = { "only-verified" => true }
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: config)
      expect(scanner).not_to receive(:report_failure)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should fail when there are secrets and not --only-verified is false' do
      repo = Salus::Repo.new('spec/fixtures/secrets')
      config = { "only-verified" => false }
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: config)
      expect(scanner).to receive(:report_failure).and_call_original
      scanner.run

      report_h = scanner.report.to_h
      expect(report_h[:passed]).to eq(false)
      expected_log0 = { "Leaked Credential" => "216ce860c78081b83f255cad4d032361677"\
                                               "e4aea87dacecd387e62505e1e4a50dd947b"\
                                               "3ce9166b70d8b9aaa45215c1b512c518b53"\
                                               "84e5067ee7d29011da0efb4",
                        "File" => "logins.txt",
                        "Line Num" => 2,
                        "ID" => "FlatIO-PLAIN",
                        "Verified" => false }
      expected_log1 = { "Leaked Credential" => "jdbc:postgresql://localhost:5432/test?user=test"\
                                               "&password=ABCD&loggerLevel=DEBUG&&&"\
                                               "loggerFile=./blah.jsp",
                       "File" => "url.txt",
                        "Line Num" => 1,
                       "ID" => "JDBC-PLAIN",
                       "Verified" => false }
      expected_log2 = { "Leaked Credential" => "jdbc:postgresql://localhost:2345/test?user=test"\
                                               "&password=DCBA&loggerLevel=DEBUG&&&"\
                                               "loggerFile=./blah.jsp",
                       "File" => "url.txt",
                        "Line Num" => 2,
                       "ID" => "JDBC-PLAIN",
                       "Verified" => false }
      logs = JSON.parse(report_h[:logs])
      expect(logs.size).to eq(3)
      expect(logs).to include(expected_log0)
      expect(logs).to include(expected_log1)
      expect(logs).to include(expected_log2)
      expect(report_h[:warn]).to eq({})
      expect(report_h[:info]).to eq({})
      expect(report_h[:errors]).to eq([])
    end

    it 'should honor exceptions in the config to eliminate one of the findings' do
      repo = Salus::Repo.new('spec/fixtures/secrets')
      config = { "only-verified" => false,
                "exceptions" => [{ "advisory_id" => "JDBC-PLAIN",
                                  "changed_by" => "me",
                                  "notes" => "false positive because ..." }] }
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: config)
      expect(scanner).to receive(:report_failure).and_call_original
      scanner.run

      report_h = scanner.report.to_h
      expect(report_h[:passed]).to eq(false)
      expected_log0 = { "Leaked Credential" => "216ce860c78081b83f255cad4d032361677"\
                                               "e4aea87dacecd387e62505e1e4a50dd947b"\
                                               "3ce9166b70d8b9aaa45215c1b512c518b53"\
                                               "84e5067ee7d29011da0efb4",
                        "File" => "logins.txt",
                        "Line Num" => 2,
                        "ID" => "FlatIO-PLAIN",
                        "Verified" => false }
      logs = JSON.parse(report_h[:logs])
      expect(logs.size).to eq(1)
      expect(logs[0]).to eq(expected_log0)
      expect(report_h[:warn]).to eq({})
      expect(report_h[:info]).to eq({})
      expect(report_h[:errors]).to eq([])
    end

    it 'should honor exceptions in the config to eliminate all findings' do
      repo = Salus::Repo.new('spec/fixtures/secrets')
      config = { "only-verified" => false,
                "exceptions" => [{ "advisory_id" => "JDBC-PLAIN",
                                  "changed_by" => "me",
                                  "notes" => "false positive because ..." },
                                 { "advisory_id" => "FlatIO-PLAIN",
                                   "changed_by" => "me",
                                   "notes" => "false positive because ..." }] }
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: config)
      scanner.run

      report_h = scanner.report.to_h
      expect(report_h[:passed]).to eq(true)
      expect(report_h[:logs]).to be_nil
      expect(report_h[:warn]).to eq({})
      expect(report_h[:info]).to eq({})
      expect(report_h[:errors]).to eq([])
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/secrets')
        scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return *' do
        langs = Salus::Scanners::Trufflehog.supported_languages
        expect(langs).to eq(['*'])
      end
    end
  end
end
