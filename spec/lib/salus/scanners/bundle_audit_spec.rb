require_relative '../../../spec_helper.rb'

describe Salus::Scanners::BundleAudit do
  describe '#run' do
    it 'should check for updates to the CVE DB' do
      repo = Salus::Repo.new('spec/fixtures/bundle_audit/no_cves')
      scanner = Salus::Scanners::BundleAudit.new(repository: repo, config: {})

      # Mock out the system() call and ensure it was called
      expect(Bundler::Audit::Database)
        .to receive(:system)
        .with("git", "pull", "--quiet", "origin", "master")
        .and_return(true)

      scanner.run
    end

    context 'CVEs in Gemfile.lock' do
      it 'should record failure and record the STDOUT from bundle-audit' do
        # TODO: create fake placeholder gems but such that you can actually bundle install them.
        # This will prevent new CVEs coming out from causing tests to fail.
        repo = Salus::Repo.new('spec/fixtures/bundle_audit/cves_found')
        scanner = Salus::Scanners::BundleAudit.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        vuln = info[:vulnerabilities][0]

        expect(vuln[:name]).to eq('actionview')
        expect(vuln[:version]).to eq('4.1.15')
        expect(vuln[:cve]).to eq('CVE-2016-6316')
        expect(vuln[:cvss]).to eq(nil)
      end
    end

    context 'insecure sources in Gemfile' do
      it 'should record failure and report results' do
        repo = Salus::Repo.new('spec/fixtures/bundle_audit/insecure_source')
        scanner = Salus::Scanners::BundleAudit.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:vulnerabilities])
          .to include(type: "InsecureSource", source: "http://rubygems.org/")
      end
    end

    context 'no CVEs in Gemfile.lock' do
      it 'should report success' do
        repo = Salus::Repo.new('spec/fixtures/bundle_audit/no_cves')
        scanner = Salus::Scanners::BundleAudit.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:ignored_cves]).to eq([])
      end
    end

    context 'no CVEs in Gemfile.lock when ignoring CVEs' do
      it 'should record success and report on the ignored CVEs' do
        repo = Salus::Repo.new('spec/fixtures/bundle_audit/passes_with_ignores')
        scanner = Salus::Scanners::BundleAudit.new(
          repository: repo,
          config: { 'ignore' => %w[CVE-2012-3464 CVE-2015-3227] }
        )

        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:ignored_cves]).to eq(%w[CVE-2012-3464 CVE-2015-3227])
      end
    end
  end

  describe '#should_run?' do
    it 'should return false if Gemfile.lock not present' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      expect(repo.gemfile_lock_present?).to eq(false)

      scanner = Salus::Scanners::BundleAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if Gemfile.lock is present' do
      repo = Salus::Repo.new('spec/fixtures/bundle_audit/no_cves')
      expect(repo.gemfile_lock_present?).to eq(true)

      scanner = Salus::Scanners::BundleAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end
end
