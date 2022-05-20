require_relative '../../../../spec_helper.rb'

describe Salus::Scanners::PackageVersion::NPMPackageScanner do
  let(:path) { 'spec/fixtures/package_version/npm_package_version_scanner/' }
  let(:config_file) { YAML.load_file("#{path}/salus.yml") }
  let(:config_file_with_block) { YAML.load_file("#{path}/salus_fail_with_block.yml") }
  let(:scanner_config) { config_file['scanner_configs']["NPMPackageScanner"] }
  let(:scanner_config_with_block) { config_file_with_block['scanner_configs']["NPMPackageScanner"] }

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

    it 'should return true if package lock has empty dependencies' do
      repo = Salus::Repo.new('spec/fixtures/npm_audit/failure_empty_lock')
      scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#run' do
    context 'package-lock file present' do
      it 'should fail when package in repo does not fall within the specified package range' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/failure')
        scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
          config: scanner_config)
        scanner.run
        logs = scanner.report.to_h[:logs]
        expect(scanner.report.passed?).to eq(false)
        expect(JSON.parse(logs)).to eq(
          [
            "Package version for (mobx) (3.6.2) is less than minimum configured version (3.6.3) "\
            "on line {13} in package-lock.json.",
            "Package version for (uglify-js) (1.2.3) is greater than maximum configured version "\
            "(0.10.3) on line {18} in package-lock.json."
          ]
        )
      end

      it 'should fail when package in repo matched blocked range' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/failure')
        scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
          config: scanner_config_with_block)
        scanner.run
        logs = scanner.report.to_h[:logs]
        expect(scanner.report.passed?).to eq(false)
        expect(JSON.parse(logs)).to eq(
          [
            "Package version for (mobx) (3.6.2) matches the configured blocked version"\
          " (3.1.1,3.6.2) on line {13} in package-lock.json."
          ]
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
        config['package_versions']['mobx']['block'] = '1.1.1'
        scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
          config: config)
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end

      it 'should pass when package-lock file exists and nothing is configured for any package' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/failure')
        config = config_file
        config['scanner_configs']["NPMPackageScanner"] = []
        scanner = Salus::Scanners::PackageVersion::NPMPackageScanner.new(repository: repo,
          config: config)
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end
    end
  end
end
