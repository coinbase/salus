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
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should fail when there are missing dependencies' do
      repo = Salus::Repo.new('spec/fixtures/cargo_audit/failure-missing-dependency')
      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should fail when there are vulnerabilities' do
      repo = Salus::Repo.new('spec/fixtures/cargo_audit/failure-vulnerability-present')
      scanner = Salus::Scanners::CargoAudit.new(repository: repo, config: {})
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
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
  end
end
