require_relative '../../../../spec_helper.rb'

describe Salus::Scanners::PackageVersion::GoPackageScanner do
  let(:path) { 'spec/fixtures/package_version/go_package_version_scanner/' }
  let(:config_file_with_block) { YAML.load_file("#{path}/salus_fail_with_block.yml") }
  let(:scanner_config_with_block) { config_file_with_block['scanner_configs']["GoPackageScanner"] }

  let(:config_file_with_range) { YAML.load_file("#{path}/salus_fail_with_range.yml") }
  let(:scanner_config_with_range) { config_file_with_range['scanner_configs']["GoPackageScanner"] }

  let(:config_file_pass) { YAML.load_file("#{path}/salus_pass.yml") }
  let(:scanner_config_pass) { config_file_pass['scanner_configs']["GoPackageScanner"] }

  let(:config_file) { YAML.load_file("#{path}/salus.yml") }
  let(:scanner_config) { config_file['scanner_configs']["GoPackageScanner"] }

  describe '#should_run?' do
    it 'should return false when go.sum file is absent' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::PackageVersion::GoPackageScanner.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if go.sum is present' do
      repo = Salus::Repo.new('spec/fixtures/osv/go_osv/success_no_vulnerability')
      scanner = Salus::Scanners::PackageVersion::GoPackageScanner.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#run' do
    context 'go.sum file present' do
      it 'should fail when package in repo does not fall within the specified package range' do
        repo = Salus::Repo.new('spec/fixtures/osv/go_osv/failure_vulnerability_present')
        scanner = Salus::Scanners::PackageVersion::GoPackageScanner.new(repository: repo,
          config: scanner_config_with_range)
        scanner.run
        logs = scanner.report.to_h[:logs]
        expect(scanner.report.passed?).to eq(false)
        expect(JSON.parse(logs)).to eq(
          [
            "Package version for (github.com/syncthing/syncthing) (1.14.0) is greater"\
              " than maximum configured version (1.0.5) in go.sum."
          ]
        )
      end

      it 'should fail when package in repo matched blocked range' do
        repo = Salus::Repo.new('spec/fixtures/osv/go_osv/failure_vulnerability_present')
        scanner = Salus::Scanners::PackageVersion::GoPackageScanner.new(repository: repo,
          config: scanner_config_with_block)
        scanner.run
        logs = scanner.report.to_h[:logs]
        expect(scanner.report.passed?).to eq(false)
        expect(JSON.parse(logs)).to eq(
          [
            "Package version for (github.com/syncthing/syncthing) (1.14.0) matches"\
              " the configured blocked version (1.14.0,1.5.0) in go.sum."
          ]
        )
      end

      it 'should pass when go.sum file exists and nothing is configured for the scanner' do
        repo = Salus::Repo.new('spec/fixtures/osv/go_osv/success_no_vulnerability')
        scanner = Salus::Scanners::PackageVersion::GoPackageScanner.new(repository: repo,
            config: scanner_config)
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end

      it 'should pass when package falls within specified package range' do
        repo = Salus::Repo.new('spec/fixtures/osv/go_osv/success_no_vulnerability')
        scanner = Salus::Scanners::PackageVersion::GoPackageScanner.new(repository: repo,
          config: scanner_config_pass)
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end
    end
  end
end
