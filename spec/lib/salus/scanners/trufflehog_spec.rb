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
      expected_log0 = { "SHA256 of Leaked Credential" => "2d00fc02b2d554da2a58feb7bac"\
                                                      "53673126f5c10f7c0a718e49e63"\
                                                      "5c489bf505",
                        "File" => "logins.txt",
                        "Line Num" => 2,
                        "ID" => "FlatIO-PLAIN",
                        "Verified" => false }
      expected_log1 = { "SHA256 of Leaked Credential6" => "e364ca3424d2454bc630a574e16"\
                                                      "9102b6d6be06189a2038badb969"\
                                                      "cf47755abe",
                       "File" => "url.txt",
                        "Line Num" => 1,
                       "ID" => "JDBC-PLAIN",
                       "Verified" => false }
      expected_log2 = { "SHA256 of Leaked Credential" => "8f839fbea674797911361d91124"\
                                                      "50478e280b982321c22363ca7a7"\
                                                      "4f36a4bbd6",
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
      expected_log0 = { "SHA256 of Leaked Credential" => "2d00fc02b2d554da2a58feb7"\
                                                      "bac53673126f5c10f7c0a718"\
                                                      "e49e635c489bf505",
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
