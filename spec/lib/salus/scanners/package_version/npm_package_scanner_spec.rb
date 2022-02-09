require_relative '../../../../spec_helper.rb'

describe Salus::Scanners::PackageVersion::NPMPackageScanner do
  let(:path) { 'spec/fixtures/package_version/npm_package_version_scanner/' }
  let(:config_file) { YAML.load_file("#{path}/salus.yml") }
  let(:scanner_config) { config_file['scanner_configs']["NPMPackageScanner"] }

  describe '#should_run?' do
    it 'should return false in the absence of package.json and friends' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      expect(repo.package_lock_json_present?).to eq(false)

      scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if package.json is present' do
      repo = Salus::Repo.new('spec/fixtures/npm_audit/success')
      expect(repo.package_lock_json_present?).to eq(true)

      scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end
  describe '#run' do
    context 'with no package-json presentin  project' do
      it 'should record error to scanner report' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
        config: scanner_config)

        expect(scanner.should_run?).to eq(false)

        scanner.run

        expect(scanner.report.passed?).to eq(true)
      end
    end
  end
  describe '#run' do
    context 'with no package-json presentin  project' do
      it 'should record error to scanner report' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
        config: scanner_config)

        expect(scanner.should_run?).to eq(false)

        scanner.run

        expect(scanner.report.passed?).to eq(true)
      end
    end
  end
end
