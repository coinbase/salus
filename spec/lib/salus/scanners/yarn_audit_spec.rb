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

      repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure-2')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should fail with the correct attr values' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure-4')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      vulns = JSON.parse(scanner.report.to_h[:info][:stdout])
      expect(vulns.size).to eq(5)
      vuln0 = { "Package" => "uglify-js",
                "Patched in" => ">= 2.4.24",
                "Dependency of" => "uglify-js",
                "More info" => "https://www.npmjs.com/advisories/39",
                "Severity" => "low",
                "Title" => "Incorrect Handling of Non-Boolean Comparisons During Minification",
                "ID" => 39 }
      vuln1 = { "Package" => "uglify-js",
                "Patched in" => ">=2.6.0",
                "Dependency of" => "uglify-js",
                "More info" => "https://www.npmjs.com/advisories/48",
                "Severity" => "low",
                "Title" => "Regular Expression Denial of Service",
                "ID" => 48 }
      vuln2 = { "Package" => "dot-prop",
                "Patched in" => ">=4.2.1 <5.0.0 || >=5.1.1",
                "Dependency of" => "dot-prop",
                "More info" => "https://www.npmjs.com/advisories/1213",
                "Severity" => "high",
                "Title" => "Prototype Pollution",
                "ID" => 1213 }
      vuln3 = { "Package" => "yargs-parser",
                "Patched in" => ">=13.1.2 <14.0.0 || >=15.0.1 <16.0.0 || >=18.1.2",
                "Dependency of" => "yargs-parser",
                "More info" => "https://www.npmjs.com/advisories/1500",
                "Severity" => "low",
                "Title" => "Prototype Pollution",
                "ID" => 1500 }
      vuln4 = { "Package" => "lodash",
                "Patched in" => ">=4.17.19",
                "Dependency of" => "lodash",
                "More info" => "https://www.npmjs.com/advisories/1523",
                "Severity" => "low",
                "Title" => "Prototype Pollution",
                "ID" => 1523 }

      expect(vulns[0]).to eq(vuln0)
      expect(vulns[1]).to eq(vuln1)
      expect(vulns[2]).to eq(vuln2)
      expect(vulns[3]).to eq(vuln3)
      expect(vulns[4]).to eq(vuln4)
    end

    it 'should fail with error if there are errors' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure-3')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run

      report = scanner.report.to_h
      expect(report.fetch(:passed)).to eq(false)
      info = scanner.report.to_h.fetch(:info)
      err_msg = "Couldn't find any versions for \"classnames-repo-does-not-exist\" that matches"
      expect(info[:stderr]).to include(err_msg)
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

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end
end
