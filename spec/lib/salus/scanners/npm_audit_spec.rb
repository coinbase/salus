require_relative '../../../spec_helper.rb'

describe Salus::Scanners::NPMAudit do
  def load_config(fixture_dir)
    YAML.load_file("#{fixture_dir}/salus.yaml")['scanner_configs']['NPMAudit']
  end

  describe '#run' do
    context 'CVEs in package.json' do
      it 'should fail, recording advisory ids and npm output' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/failure')
        scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info.key?(:npm_audit_output)).to eq(true)

        expect(info).to include(
          prod_advisories: %w[39 48],
          dev_advisories: [],
          unexcepted_prod_advisories: %w[39 48],
          exceptions: [],
          prod_exceptions: [],
          dev_exceptions: [],
          useless_exceptions: []
        )
      end
    end

    context 'no CVEs in package.json' do
      it 'should record success' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/success')
        scanner = Salus::Scanners::NPMAudit.new(repository: repo, config: {})
        scanner.run
        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)

        expect(info.key?(:npm_audit_output)).to eq(true)

        expect(info).to include(
          prod_advisories: [],
          dev_advisories: [],
          unexcepted_prod_advisories: []
        )
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

        expect(info.key?(:npm_audit_output)).to eq(true)

        expect(info).to include(
          prod_advisories: %w[39 48],
          dev_advisories: [],
          unexcepted_prod_advisories: [],
          exceptions: %w[39 48],
          prod_exceptions: %w[39 48],
          dev_exceptions: [],
          useless_exceptions: []
        )
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
