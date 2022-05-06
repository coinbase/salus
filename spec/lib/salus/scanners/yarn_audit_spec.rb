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

      repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure_yarn_3')
      config_data = YAML.load_file('spec/fixtures/yarn_audit/failure_yarn_3/'\
                                    'salus.yaml')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: config_data)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    let(:vuln_0_id) { 1_004_708 } # was 39, 1004707
    let(:vuln_1_id) { 1_004_774 } # was 48, 1004708
    let(:vuln_2_id) { 1_004_036 } # was 1213
    let(:vuln_3_id) { 1_003_019 } # was 1500
    let(:vuln_4_id) { 1_002_847 } # was 1673
    let(:vuln_5_id) { 1_004_063 } # was 1523

    it 'should fail with the correct attr values' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure-4')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      vulns = JSON.parse(scanner.report.to_h[:info][:stdout]).sort { |a, b| a["ID"] <=> b["ID"] }
      expect(vulns.size).to eq(7)

      vulns.each do |vul|
        ["Package", "Patched in", "Dependency of", "More info", "Severity", "Title"].each do |attr|
          expect(vul[attr]).to be_kind_of(String)
          expect(vul[attr]).not_to be_empty
        end
        expect(vul["ID"]).to be_kind_of(Integer)
      end

      repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure_yarn_3')
      config_data = YAML.load_file('spec/fixtures/yarn_audit/failure_yarn_3/'\
        'salus.yaml')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: config_data)
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      vulns = JSON.parse(scanner.report.to_h[:info][:stdout]).sort { |a, b| a["ID"] <=> b["ID"] }
      expect(vulns.size).to eq(17)

      vulns.each do |vul|
        ["Package", "Patched in", "Dependency of", "More info", "Severity", "Title"].each do |attr|
          expect(vul[attr]).to be_kind_of(String)
          expect(vul[attr]).not_to be_empty
        end
        expect(vul["ID"]).to be_kind_of(Integer)
      end

      id_vuls = vulns.select { |v| v['ID'] == 1_067_329 }
      expect(id_vuls.size).to eq(1)
      # vul has two merged dependdency of
      expected_vul = { "Package" => "glob-parent",
                      "Patched in" => ">=5.1.2",
                      "Dependency of" => "chokidar, gulp",
                      "More info" => "https://www.npmjs.com/advisories/1067329",
                      "Severity" => "high",
                      "Title" => "Regular expression denial of service in glob-parent",
                      "ID" => 1_067_329 }
      expect(id_vuls[0]).to eq(expected_vul)

      id_vuls = vulns.select { |v| v['ID'] == 1_067_342 }
      expect(id_vuls.size).to eq(1)
      # vul has 1 dependency of
      expected_vul = { "Package" => "minimist",
                      "Patched in" => ">=1.2.6",
                      "Dependency of" => "gulp-cssmin",
                      "More info" => "https://www.npmjs.com/advisories/1067342",
                      "Severity" => "critical",
                      "Title" => "Prototype Pollution in minimist",
                      "ID" => 1_067_342 }
      expect(id_vuls[0]).to eq(expected_vul)
    end

    it 'should fail with error if there are errors' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure-3')
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run

      report = scanner.report.to_h
      expect(report.fetch(:passed)).to eq(false)
      info = scanner.report.to_h.fetch(:info)
      err_msg = "Received malformed response from registry for \"classnames-repo-does-not-exist\""
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
        repo = Salus::Repo.new('spec/fixtures/yarn_audit/success')
        scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version

        repo = Salus::Repo.new('spec/fixtures/yarn_audit/failure_yarn_3')
        scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return javascript' do
        langs = Salus::Scanners::YarnAudit.supported_languages
        expect(langs).to eq(['javascript'])
      end
    end
  end
end
