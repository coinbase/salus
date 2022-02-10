require_relative '../../../../spec_helper.rb'

describe Salus::Scanners::PackageVersion::NPMPackageScanner do
  let(:path) { 'spec/fixtures/package_version/npm_package_version_scanner/' }
  let(:config_file) { YAML.load_file("#{path}/salus.yml") }
  let(:scanner_config) { config_file['scanner_configs']["NPMPackageScanner"] }

  describe '#should_run?' do
    it 'should return false when package lock file is absent' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if package lock is present' do
      repo = Salus::Repo.new('spec/fixtures/npm_audit/success')
      scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#run' do
    context 'package-lock file present' do
      it 'should fail when specified package is not present in the repository' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
        config: scanner_config)
        scanner.run
        message = scanner.report.to_h[:errors][0][:message]
        expect(scanner.report.passed?).to eq(false)
        expect(message).to eq("Package mobx was not found in the package-lock.json")
      end

      it 'should fail when package in repo does not fall within the specified package range' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/failure')
        scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
          config: scanner_config)
        scanner.run
        expect(scanner.report.passed?).to eq(false)
        expect(scanner.report.to_h).to include(
          { errors: [{ message: "Package version for (mobx) (3.6.2)is less than minimum configured"\
            " version (3.6.3) on line {13} in package-lock.json" }, { message: "Package version fo"\
              "r (uglify-js) (1.2.3) is greater than maximum configured version (0.10.3) on line "\
              "{18} in package-lock.json" }] }
        )
      end

      it 'should pass when package-lock file exists and nothing is configured for the scanner' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/failure')
        scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
          config: {})
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end

      it 'should pass when package falls within specified package range' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/failure')
        config = scanner_config
        config['package_versions']['mobx']['min_version'] = '3.6.0'
        config['package_versions']['uglify-js']['max_version'] = '1.3.4'
        scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
          config: config)
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end
    end
  end
end
