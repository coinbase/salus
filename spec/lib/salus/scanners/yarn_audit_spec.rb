require_relative '../../../spec_helper.rb'

describe Salus::Scanners::YarnAudit do
  describe '#should_run?' do
    it 'should return false in the absence of package.json and friends' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      expect(repo.yarn_lock_present?).to eq(false)

      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if package.json is present' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/success')
      expect(repo.yarn_lock_present?).to eq(true)

      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#run' do
    it 'should fail when there are CVEs' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      vulns = JSON.parse(scanner.report.to_h[:info][:stdout])
      expect(vulns.size).to eq(2)
      vuln0 = { "Package" => "uglify-js",
                "Patched in" => ">= 2.4.24",
                "Dependency of" => "uglify-js",
                "Path" => "uglify-js",
                "More info" => "https://www.npmjs.com/advisories/39",
                "severity" => "low",
                "title" => "Incorrect Handling of Non-Boolean Comparisons During Minification",
                "id" => 39 }
      vuln1 = { "Package" => "uglify-js",
                "Patched in" => ">=2.6.0",
                "Dependency of" => "uglify-js",
                "Path" => "uglify-js",
                "More info" => "https://www.npmjs.com/advisories/48",
                "severity" => "low",
                "title" => "Regular Expression Denial of Service",
                "id" => 48 }
      expect(vulns[0]).to eq(vuln0)
      expect(vulns[1]).to eq(vuln1)

      repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure-2')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should fail with error if there are errors' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure-3')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run

      report = scanner.report.to_h
      expect(report.fetch(:passed)).to eq(false)
      info = scanner.report.to_h.fetch(:info)
      expect(info[:stderr]).to include("classnames-repo-does-not-exist: Not found")
    end

    it 'should pass if vulnerable devDependencies are excluded' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/success_with_exclusions')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)

      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {
                                                 "exclude_groups" =>
                                                 %w[devDependencies]
                                               })
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should warn if only optionalDependencies are scanned' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/success')

      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {
                                                 "exclude_groups" =>
                                                 %w[devDependencies dependencies]
                                               })

      scanner.run
      expect(scanner.report.to_h.fetch(:warn)).to include(
        scanner_misconfiguration: "Scanning only optionalDependencies!"
      )
    end

    it 'should error if all 3 groups are excluded' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/success')

      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {
                                                 "exclude_groups" => %w[devDependencies
                                                                        dependencies
                                                                        optionalDependencies]
                                               })
      scanner.run
      expect(scanner.report.to_h.fetch(:errors)).to include(
        message: "No dependencies were scanned!"
      )
    end
  end
end
