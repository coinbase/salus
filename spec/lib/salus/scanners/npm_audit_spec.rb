require_relative '../../../spec_helper.rb'

describe Salus::Scanners::NPMAudit do
  describe '#should_run?' do
    it 'should return false in the absence of package.json and friends' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      expect(repo.package_json_present?).to eq(false)
      expect(repo.package_lock_json_present?).to eq(false)

      scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if package.json is present' do
      repo = Salus::Repo.new('spec/fixtures/npm_audit/success')
      expect(repo.package_lock_json_present?).to eq(true)

      scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit')
        scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#audit_command_with_options' do
    it 'should return default audit command if no options have been provided' do
      repo = Salus::Repo.new('spec/fixtures/npm_audit')
      scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: {})
      expect(scanner.send(:audit_command_with_options)).to eql("npm audit --json")
    end

    it 'should return audit command with configured options' do
      repo = Salus::Repo.new('spec/fixtures/npm_audit')
      scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: { "production" => true })
      expect(scanner.send(:audit_command_with_options)).to eql("npm audit --json --production")
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return javascript' do
        langs = Salus::Scanners::NPMAudit.supported_languages
        expect(langs).to eq(['javascript'])
      end
    end
  end
end
