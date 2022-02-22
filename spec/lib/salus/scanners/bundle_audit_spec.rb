require_relative '../../../spec_helper.rb'

describe Salus::Scanners::BundleAudit do
  describe '#run' do
    it 'should check for updates to the CVE DB' do
      repo = Salus::Repo.new('spec/fixtures/bundle_audit/no_cves')
      scanner = Salus::Scanners::BundleAudit.new(repository: repo, config: {})

      # Mock out the system() call and ensure it was called
      expect(Bundler::Audit::Database)
        .to receive(:update!).and_return(true)

      scanner.run
    end

    it 'runs cleanly against a project bundled with Bundler 2' do
      repo = Salus::Repo.new('spec/fixtures/bundle_audit/bundler_2')
      scanner = Salus::Scanners::BundleAudit.new(repository: repo, config: {})
      scanner.run
      expect(scanner.report.passed?).to eq(true)
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

        expect(vuln[:name]).to eq('actionpack')
        expect(vuln[:version]).to eq('4.1.15')
        expect(vuln[:cve]).to include('CVE-')
        expect(vuln[:cvss]).to eq(nil)
        expect(vuln[:line_number]).to eq(8)
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
          .to include(type: "InsecureSource", source: "http://rubygems.org/", line_number: 2)
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
          config: { 'ignore' => %w[CVE-2012-3464 CVE-2015-3227 CVE-2020-8165] }
        )

        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:ignored_cves]).to eq(%w[CVE-2012-3464 CVE-2015-3227 CVE-2020-8165])
      end
    end

    context 'exceptions with expirations' do
      let(:repo) { Salus::Repo.new('spec/fixtures/bundle_audit/passes_with_ignores') }

      before(:each) do
        allow(Date).to receive(:today).and_return Date.new(2021, 12, 31)
      end

      it 'should apply active exceptions' do
        scanner = Salus::Scanners::BundleAudit.new(
          repository: repo,
          config: { 'exceptions' => [
            { 'advisory_id' => "CVE-2012-3464", 'expiration' => '2022-12-31',
              'changed_by' => 'appsec', 'notes' => 'foo' },
            { 'advisory_id' => "CVE-2015-3227", 'changed_by' => 'appsec', 'notes' => 'foo' },
            { 'advisory_id' => "CVE-2020-8165", 'changed_by' => 'appsec', 'notes' => 'foo' }
          ] }
        )

        scanner.run
        expect(scanner.report.passed?).to eq(true)
        info = scanner.report.to_h.fetch(:info)
        expect(info[:ignored_cves]).to eq(%w[CVE-2012-3464 CVE-2015-3227 CVE-2020-8165])
      end

      it 'should not apply expired exceptions' do
        scanner = Salus::Scanners::BundleAudit.new(
          repository: repo,
          config: { 'exceptions' => [
            { 'advisory_id' => "CVE-2012-3464", 'expiration' => '2020-12-31',
              'changed_by' => 'appsec', 'notes' => 'foo' }
          ] }
        )

        scanner.run
        expect(scanner.report.passed?).to eq(false)
        info = scanner.report.to_h.fetch(:info)
        expect(info[:ignored_cves]).to eq([])

        vul = info[:vulnerabilities][0]
        expect(vul[:name]).to eq('activesupport')
        expect(vul[:version]).to eq('2.3.18')
        expect(vul[:line_number]).to eq(4)
      end

      it 'should record success and report on the ignored CVEs' do
        repo = Salus::Repo.new('spec/fixtures/bundle_audit/passes_with_ignores')
        scanner = Salus::Scanners::BundleAudit.new(
          repository: repo,
          config: { 'ignore' => %w[CVE-2012-3464 CVE-2015-3227 CVE-2020-8165] }
        )

        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:ignored_cves]).to eq(%w[CVE-2012-3464 CVE-2015-3227 CVE-2020-8165])
      end
    end

    context 'with local db' do
      it 'should report vulns from both local db and ruby advisory db' do
        dir = 'spec/fixtures/bundle_audit/local_db'
        repo = Salus::Repo.new(dir)
        scanner = Salus::Scanners::BundleAudit.new(
          repository: repo,
          config: { 'local_db' => dir + '/good_local_db' }
        )

        scanner.run
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        vulns = info[:vulnerabilities]
        cves = vulns.map { |v| v[:cve] }
        # vul found in ruby-advisory-db
        expect(cves).to include('CVE-2020-7663')
        # vul found in local db
        expect(cves).to include('ABCD-2021-001')
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

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::BundleAudit.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return ruby' do
        langs = Salus::Scanners::BundleAudit.supported_languages
        expect(langs).to eq(['ruby'])
      end
    end
  end

  describe '#valid_local_db?' do
    it 'should detect valid/invalid local dbs' do
      dir_path = 'spec/fixtures/bundle_audit/local_db'
      repo = Salus::Repo.new(dir_path)
      scanner = Salus::Scanners::BundleAudit.new(repository: repo, config: {})
      expect(scanner.valid_local_db?(dir_path + '/good_local_db')).to eq(true)
      expect(scanner.valid_local_db?(dir_path + '/bad_local_db')).to eq(false)
    end
  end
end
