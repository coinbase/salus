require_relative '../../../spec_helper.rb'

describe Salus::Scanners::NPMAudit do
  let(:report) { Salus::Report.new }
  let(:scan_report) { json_report['scans']['NPMAudit'] }
  let(:scan_errors) { json_report['errors']['NPMAudit'] }

  describe '#run' do
    context 'CVEs in package.json' do
      it 'should record failure and stderr from npm audit' do
        scanner = Salus::Scanners::NPMAudit.new(
          repository: Salus::Repo.new('spec/fixtures/npm_audit/failure'),
          report: report,
          config: {}
        )
        scanner.run

        expect(scan_report['passed']).to eq(false)
        expect(scan_report['info'].keys).to eq(%w[package_lock_missing npm_audit_output])
        expect(scan_report['info']['npm_audit_output'].length).to eq(1)
        # Ensure 2 vulns were found
        expect(scan_report['info']['npm_audit_output'][0]['advisories'].keys).to eq(%w[39 48])
      end
    end

    context 'no CVEs in package.json' do
      it 'should record success' do
        scanner = Salus::Scanners::NPMAudit.new(
          repository: Salus::Repo.new('spec/fixtures/npm_audit/success'),
          report: report,
          config: {}
        )
        scanner.run

        expect(scan_report['passed']).to eq(true)
        expect(scan_report['info'].keys).to eq(['package_lock_missing'])
      end
    end

    context 'no CVEs in package.json when ignoring CVEs' do
      it 'should record success and report on the ignored CVEs' do
        scanner = Salus::Scanners::NPMAudit.new(
          repository: Salus::Repo.new('spec/fixtures/npm_audit/success_with_exceptions'),
          report: report,
          config: YAML.load_file(
            "spec/fixtures/npm_audit/success_with_exceptions/salus.yaml"
          )['scanner_configs']['NPMAudit'] # Mock what Salus does under the hood
        )
        scanner.run
        expect(scan_report['passed']).to eq(true)
        expect(
          scan_report['info'].keys.sort
        ).to eq(%w[exceptions npm_audit_output package_lock_missing])
        expect(scan_report['info']['exceptions'].length).to eq(2)
        expect(scan_report['info']['exceptions'].map { |x| x['advisory_id'] }.sort).to eq(%w[39 48])
      end
    end
  end

  describe '#should_run?' do
    context 'no relevant files present' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.package_json_present?).to eq(false)
        scanner = Salus::Scanners::NPMAudit.new(repository: repo, report: report, config: {})
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'package.json is present' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/success')
        expect(repo.package_json_present?).to eq(true)
        scanner = Salus::Scanners::NPMAudit.new(repository: repo, report: report, config: {})
        expect(scanner.should_run?).to eq(true)
      end
    end
  end
end
