require_relative '../../../spec_helper.rb'

describe Salus::Scanners::BundleAudit do
  let(:blank_config) { { 'ignore' => [] } }
  let(:report) { Salus::Report.new }
  let(:scan_report) { json_report['scans']['BundleAudit'] }
  let(:scan_errors) { json_report['errors']['BundleAudit'] }

  describe '#run' do
    it 'should check for updates to the CVE DB' do
      scanner = Salus::Scanners::BundleAudit.new(
        repository: Salus::Repo.new('spec/fixtures/bundle_audit/no_cves'),
        report: report,
        config: blank_config
      )

      # Mock out the system() call and ensure it was called
      expect(Bundler::Audit::Database).to(
        receive(:system).with(
          "git", "pull", "--quiet", "origin", "master"
        ).and_return(true)
      )

      scanner.run
    end

    context 'broken Gemfile.lock' do
      it 'should throw/rescue and report an error for an invalid directory' do
        scanner = Salus::Scanners::BundleAudit.new(
          repository: Salus::Repo.new('spec/fixtures/blank_repository'),
          report: report,
          config: blank_config
        )
        scanner.run
        expect(scan_errors).to include(
          'message' => "Errno::ENOENT - Invalid directory (directory doesn't exist)"
        )
      end
    end

    context 'CVEs in Gemfile.lock' do
      it 'should record failure and record the STDOUT from bundle-audit' do
        # TODO: create fake placeholder gems but such that you can actually bundle install them.
        # This will prevent new CVEs coming out from causing tests to fail.
        scanner = Salus::Scanners::BundleAudit.new(
          repository: Salus::Repo.new('spec/fixtures/bundle_audit/cves_found'),
          report: report,
          config: blank_config
        )
        scanner.run

        bundle_audit_results = report.to_h[:scans]['BundleAudit']
        actionview_result = bundle_audit_results['info']['unpatched_gem'][0]

        expect(scan_report['passed']).to eq(false)
        expect(actionview_result[:name]).to eq('actionview')
        expect(actionview_result[:version]).to eq('4.1.15')
        expect(actionview_result[:cve]).to eq('CVE-2016-6316')
        expect(actionview_result[:cvss]).to eq(nil)
      end
    end

    context 'insecure sources in Gemfile' do
      it 'should record failure and report results' do
        scanner = Salus::Scanners::BundleAudit.new(
          repository: Salus::Repo.new('spec/fixtures/bundle_audit/insecure_source'),
          report: report,
          config: blank_config
        )
        scanner.run

        bundle_audit_results = report.to_h[:scans]['BundleAudit']
        actionview_result = bundle_audit_results['info']['unpatched_gem'][0]

        expect(bundle_audit_results['stdout']).not_to eq(nil)
        expect(bundle_audit_results['stdout']).not_to eq('')

        expect(scan_report['passed']).to eq(false)
        expect(actionview_result[:name]).to eq('actionview')
        expect(actionview_result[:version]).to eq('4.1.15')
        expect(actionview_result[:cve]).to eq('CVE-2016-6316')
        expect(actionview_result[:cvss]).to eq(nil)
      end
    end

    context 'no CVEs in Gemfile.lock' do
      it 'should record success' do
        scanner = Salus::Scanners::BundleAudit.new(
          repository: Salus::Repo.new('spec/fixtures/bundle_audit/no_cves'),
          report: report,
          config: blank_config
        )
        scanner.run
        expect(scan_report['passed']).to eq(true)
        expect(scan_report['ignored_cve']).to be_nil
      end
    end

    context 'no CVEs in Gemfile.lock when ignoring CVEs' do
      it 'should record success and report on the ignored CVEs' do
        scanner = Salus::Scanners::BundleAudit.new(
          repository: Salus::Repo.new('spec/fixtures/bundle_audit/passes_with_ignores'),
          report: report,
          config: { 'ignore' => %w[CVE-2012-3464 CVE-2015-3227] }
        )
        scanner.run
        expect(scan_report['passed']).to eq(true)
        expect(scan_report['info']['ignored_cves']).to eq(%w[CVE-2012-3464 CVE-2015-3227])
      end
    end
  end

  describe '#should_run?' do
    context 'Gemfile.lock not present' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.gemfile_lock_present?).to eq(false)
        scanner = Salus::Scanners::BundleAudit.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'Gemfile.lock is present' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/bundle_audit/no_cves')
        expect(repo.gemfile_lock_present?).to eq(true)
        scanner = Salus::Scanners::BundleAudit.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(true)
      end
    end
  end
end
