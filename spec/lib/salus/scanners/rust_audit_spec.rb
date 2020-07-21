require_relative '../../../spec_helper.rb'

describe Salus::Scanners::RustAudit do
  describe '#should_run?' do
    it 'should return false in the absence of Cargo.lock' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      expect(repo.cargo_lock_present?).to eq(false)

      scanner = Salus::Scanners::RustAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if Cargo.lock is present' do
      repo = Salus::Repo.new('spec/fixtures/rust_audit/success')
      expect(repo.cargo_lock_present?).to eq(true)

      scanner = Salus::Scanners::RustAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#run' do
    it 'should fail when there are vulnerabilities' do
      repo = Salus::Repo.new('spec/fixtures/rust_audit/failure-vulnerability-present')
      scanner = Salus::Scanners::RustAudit.new(repository: repo, config: {})
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should fail when there are missing dependencies' do
      repo = Salus::Repo.new('spec/fixtures/rust_audit/failure-missing-dependency')
      scanner = Salus::Scanners::RustAudit.new(repository: repo, config: {})
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end
  end
end
