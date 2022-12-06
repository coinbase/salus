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
  end


  describe '#run' do
    it 'should pass when there are no secrets' do
      repo = Salus::Repo.new('spec/fixtures/secrets/benign')
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})
      expect(scanner).not_to receive(:report_failure)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should fail when there are secrets' do
      repo = Salus::Repo.new('spec/fixtures/secrets')
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})
      expect(scanner).to receive(:report_failure).and_call_original
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end


    it 'should honor exceptions in the config' do
      fixture_directory = 'spec/fixtures/cargo_audit/failure-vulnerability-present'
      repo = Salus::Repo.new(fixture_directory)

      config_path = File.join(fixture_directory, 'salus.yaml')
      config = YAML.load_file(config_path)['scanner_configs']['Trufflehog']

      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: config)
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should honor exception expirations' do
      fixture_directory = 'spec/fixtures/cargo_audit/failure-vulnerability-present'
      repo = Salus::Repo.new(fixture_directory)

      config_path = File.join(fixture_directory, 'salus-expired.yaml')
      config = YAML.load_file(config_path)['scanner_configs']['Trufflehog']

      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: config)
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should send the audit log as json' do
      path = 'spec/fixtures/cargo_audit/failure-vulnerability-present'
      repo = Salus::Repo.new(path)
      audit_json = File.read(File.join(path, 'expected_audit.json'))
      json_keys = JSON.parse(audit_json).keys
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})

      expect(scanner).to receive(:log).with(json_with_keys(json_keys))
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should log pretty json' do
      path = 'spec/fixtures/cargo_audit/failure-vulnerability-present'
      repo = Salus::Repo.new(path)
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})

      expect(scanner).to receive(:log).with(pretty_json)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should report error if there were issues in running cargo audit' do
      repo = Salus::Repo.new('spec/fixtures/cargo_audit/non_project_directory')
      scanner = Salus::Scanners::Trufflehog.new(repository: repo, config: {})

      expect(scanner).to receive(:report_failure).and_call_original
      expect(scanner).not_to receive(:report_stdout)
      expect(scanner).not_to receive(:log)
      expect(scanner).to receive(:report_error).and_call_original
      error = "error: Couldn't load Cargo.lock: I/O error: I/O operation failed: " \
              "couldn't open Cargo.lock: No such file or directory (os error 2)\n"
      expect(scanner).to receive(:report_stderr).with(error)

      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
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
