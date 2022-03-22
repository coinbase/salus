require_relative '../../../../spec_helper.rb'

describe Salus::Scanners::PackageVersion::RubyPackageScanner do
  let(:path) { 'spec/fixtures/package_version/ruby_package_version_scanner/' }
  let(:config_file_with_block) { YAML.load_file("#{path}/salus_fail_with_block.yml") }
  let(:scanner_config_with_block) do
    config_file_with_block['scanner_configs']["RubyPackageScanner"]
  end

  let(:config_file_with_range) { YAML.load_file("#{path}/salus_fail_with_range.yml") }
  let(:scanner_config_with_range) do
    config_file_with_range['scanner_configs']["RubyPackageScanner"]
  end

  let(:config_file_pass) { YAML.load_file("#{path}/salus_pass.yml") }
  let(:scanner_config_pass) { config_file_pass['scanner_configs']["RubyPackageScanner"] }

  let(:config_file) { YAML.load_file("#{path}/salus.yml") }
  let(:scanner_config) { config_file['scanner_configs']["RubyPackageScanner"] }

  describe '#should_run?' do
    it 'should return false when Gemfile.lock file is absent' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::PackageVersion::RubyPackageScanner.new(repository: repo,
        config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if Gemfile.lock is present' do
      repo = Salus::Repo.new('spec/fixtures/bundle_audit/no_cves')
      scanner = Salus::Scanners::PackageVersion::RubyPackageScanner.new(repository: repo,
        config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#run' do
    context 'Gemfile.lock file present' do
      it 'should fail when package in repo does not fall within the specified package range' do
        repo = Salus::Repo.new('spec/fixtures/bundle_audit/cves_found')
        scanner = Salus::Scanners::PackageVersion::RubyPackageScanner.new(repository: repo,
          config: scanner_config_with_range)
        scanner.run
        logs = scanner.report.to_h[:logs]
        expect(scanner.report.passed?).to eq(false)
        expect(JSON.parse(logs)).to eq(
          [
            "Package version for (actionmailer) (4.1.15) is greater"\
            " than maximum configured version (3.0.0) in Gemfile.lock."
          ]
        )
      end

      it 'should fail when package in repo matched blocked range' do
        repo = Salus::Repo.new('spec/fixtures/bundle_audit/cves_found')
        scanner = Salus::Scanners::PackageVersion::RubyPackageScanner.new(repository: repo,
          config: scanner_config_with_block)
        scanner.run
        logs = scanner.report.to_h[:logs]
        expect(scanner.report.passed?).to eq(false)
        expect(JSON.parse(logs)).to eq(
          [
            "Package version for (actionmailer) (4.1.15) matches"\
              " the configured blocked version (4.1.15,4.0.1) in Gemfile.lock."
          ]
        )
      end

      it 'should pass when Gemfile.lock file exists and nothing is configured for the scanner' do
        repo = Salus::Repo.new('spec/fixtures/bundle_audit/cves_found')
        scanner = Salus::Scanners::PackageVersion::RubyPackageScanner.new(repository: repo,
            config: scanner_config)
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end

      it 'should pass when package falls within specified package range' do
        repo = Salus::Repo.new('spec/fixtures/bundle_audit/cves_found')
        scanner = Salus::Scanners::PackageVersion::RubyPackageScanner.new(repository: repo,
          config: scanner_config_pass)
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end
    end
  end
end
