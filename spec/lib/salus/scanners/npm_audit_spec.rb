require_relative '../../../spec_helper.rb'

describe Salus::Scanners::NPMAudit do
  def load_config(fixture_dir)
    YAML.load_file("#{fixture_dir}/salus.yaml")['scanner_configs']['NPMAudit']
  end

  describe '#run' do
    context 'CVEs in package.json' do
      it 'should record failure and stderr from npm audit' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/failure')
        scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info.keys).to include(:npm_audit_output)
        expect(info[:npm_audit_output][:advisories].keys.map(&:to_s))
          .to contain_exactly('39', '48')
      end
    end

    context 'no CVEs in package.json' do
      it 'should record success' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/success')
        scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)
        expect(info.keys).to contain_exactly(:package_lock_missing)
      end
    end

    context 'no CVEs in package.json when ignoring CVEs' do
      it 'should record success and report on the ignored CVEs' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/success_with_exceptions')
        scanner = Salus::Scanners::NPMAudit.new(
          repository: repo,
          config: load_config('spec/fixtures/npm_audit/success_with_exceptions')
        )
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)
        expect(info.keys).to include(:exceptions, :npm_audit_output)

        exception_ids = info[:exceptions].map { |exception| exception['advisory_id'] }
        expect(exception_ids).to contain_exactly('39', '48')
      end
    end
  end

  describe '#should_run?' do
    it 'should return false in the absence of package.json and friends' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')

      expect(repo.package_json_present?).to eq(false)
      expect(repo.package_lock_json_present?).to eq(false)
      expect(repo.yarn_lock_present?).to eq(false)

      scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if package.json is present' do
      repo = Salus::Repo.new('spec/fixtures/npm_audit/success')
      expect(repo.package_json_present?).to eq(true)

      scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end
end
