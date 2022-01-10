require_relative '../../../spec_helper.rb'

describe Salus::Scanners::CargoAudit do
  describe '#should_run?' do
    it 'should return false in the absence of Cargo.lock' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      expect(repo.cargo_lock_present?).to eq(false)

      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if Cargo.lock is present' do
      repo = Salus::Repo.new('spec/fixtures/cargo_audit/success')
      expect(repo.cargo_lock_present?).to eq(true)

      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#run' do
    it 'should pass when there are no vulnerabilities' do
      repo = Salus::Repo.new('spec/fixtures/cargo_audit/success')
      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})
      expect(scanner).not_to receive(:report_failure)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should fail when there are missing dependencies' do
      repo = Salus::Repo.new('spec/fixtures/cargo_audit/failure-missing-dependency')
      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})
      expect(scanner).to receive(:report_failure).and_call_original
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should fail when there are vulnerabilities' do
      repo = Salus::Repo.new('spec/fixtures/cargo_audit/failure-vulnerability-present')
      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})
      expect(scanner).to receive(:report_failure).and_call_original
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should elevate warnings as errors' do
      path = 'spec/fixtures/cargo_audit/warnings-only'
      repo = Salus::Repo.new(path)
      audit_json = File.read(File.join(path, 'expected_log.json'))
      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})
      shell_result = ShellResultDouble.new(audit_json, '', 0).shell_result
      expect(scanner).to receive(:run_shell).and_return(shell_result)
      expect(scanner).to receive(:log).with(audit_json)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should ignore warnings if disabled in the config' do
      path = 'spec/fixtures/cargo_audit/warnings-only'
      repo = Salus::Repo.new(path)
      config = { Salus::Scanners::CargoAudit::ELEVATE_WARNINGS => false }
      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: config)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should honor exceptions in the config' do
      fixture_directory = 'spec/fixtures/cargo_audit/failure-vulnerability-present'
      repo = Salus::Repo.new(fixture_directory)

      config_path = File.join(fixture_directory, 'salus.yaml')
      config = YAML.load_file(config_path)['scanner_configs']['CargoAudit']

      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: config)
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should honor exception expirations' do
      fixture_directory = 'spec/fixtures/cargo_audit/failure-vulnerability-present'
      repo = Salus::Repo.new(fixture_directory)

      config_path = File.join(fixture_directory, 'salus-expired.yaml')
      config = YAML.load_file(config_path)['scanner_configs']['CargoAudit']

      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: config)
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should send the audit log as json' do
      path = 'spec/fixtures/cargo_audit/failure-vulnerability-present'
      repo = Salus::Repo.new(path)
      audit_json = File.read(File.join(path, 'expected_audit.json'))
      json_keys = JSON.parse(audit_json).keys
      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})

      expect(scanner).to receive(:log).with(json_with_keys(json_keys))
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should log pretty json' do
      path = 'spec/fixtures/cargo_audit/failure-vulnerability-present'
      repo = Salus::Repo.new(path)
      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})

      expect(scanner).to receive(:log).with(pretty_json)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should report error if there were issues in running cargo audit' do
      repo = Salus::Repo.new('spec/fixtures/cargo_audit/non_project_directory')
      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})

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
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/cargo_audit/non_project_directory')
        scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return rust' do
        langs = Salus::Scanners::CargoAudit.supported_languages
        expect(langs).to eq(['rust'])
      end
    end
  end
end
