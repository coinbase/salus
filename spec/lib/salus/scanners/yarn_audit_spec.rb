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

      id_vuls = vulns.select { |v| v['ID'] == 1_070_415 }
      expect(id_vuls.size).to eq(1)
      # vul has two merged dependdency of
      expected_vul = { "Package" => "nth-check",
                      "Patched in" => ">=2.0.1",
                      "Dependency of" => "rollup-plugin-postcss",
                      "More info" => "https://www.npmjs.com/advisories/1070415",
                      "Severity" => "high",
                      "Title" => "Inefficient Regular Expression Complexity in nth-check",
                      "ID" => 1_070_415 }
      expect(id_vuls[0]).to eq(expected_vul)

      id_vuls_w_paths = scanner.instance_variable_get(:@vulns_w_paths)
        .select { |v| v['ID'] == 1_070_415 }
      expect(id_vuls.size).to eq(1)
      expected_vul['Path'] = "rollup-plugin-postcss > cssnano > cssnano-preset-default > "\
                             "postcss-svgo > svgo > css-select > nth-check"
      expect(id_vuls_w_paths[0]).to eq(expected_vul)

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

      id_vuls_w_paths = scanner.instance_variable_get(:@vulns_w_paths)
        .select { |v| v['ID'] == 1_067_342 }
      expect(id_vuls.size).to eq(1)
      expected_vul['Path'] = "gulp-cssmin > gulp-util > minimist"
      expect(id_vuls_w_paths[0]).to eq(expected_vul)
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

  describe '#autofix' do
    it 'should not update if patched in major versions (direct deps only)' do
      repo_path = 'spec/fixtures/yarn_audit/failure'
      yarn_lock = File.join(repo_path, 'yarn.lock')
      package_json = File.join(repo_path, 'package.json')
      yarn_lock_fixed = File.join(repo_path, 'yarn-autofixed.lock')
      package_json_fixed = File.join(repo_path, 'package-autofixed.json')
      [yarn_lock_fixed, package_json_fixed].each do |f|
        File.delete(f) if File.exist?(f)
      end

      repo = Salus::Repo.new(repo_path)
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: { 'auto_fix' => true })
      scanner.run

      # all vuls are patched in major versions, so no updates
      expect(File.exist?(yarn_lock_fixed)).to eq(true)
      expect(File.exist?(package_json_fixed)).to eq(true)
      expect(FileUtils.compare_file(yarn_lock, yarn_lock_fixed)).to eq(true)
      package_json_content = JSON.parse(File.read(package_json))
      package_json_fixed_content = JSON.parse(File.read(package_json_fixed))
      expect(package_json_content).to eq(package_json_fixed_content)
    end

    it 'should update correctly if patched in both major/minor versions (direct deps only)' do
      repo_path = 'spec/fixtures/yarn_audit/failure-2'
      yarn_lock = File.join(repo_path, 'yarn.lock')
      package_json = File.join(repo_path, 'package.json')
      yarn_lock_fixed = File.join(repo_path, 'yarn-autofixed.lock')
      package_json_fixed = File.join(repo_path, 'package-autofixed.json')
      [yarn_lock_fixed, package_json_fixed].each do |f|
        File.delete(f) if File.exist?(f)
      end

      repo = Salus::Repo.new(repo_path)
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: { 'auto_fix' => true })
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      vulns = JSON.parse(scanner.report.to_h[:info][:stdout])
      vuln_packages = vulns.map { |v| [v['Package'], v['Patched in']] }.sort.uniq
      expected_vuln_packages = [["merge", ">=1.2.1"], ["merge", ">=2.1.1"],
                                ["uglify-js", ">=2.4.24"],
                                ["uglify-js", ">=2.6.0"]]
      expect(vuln_packages).to eq(expected_vuln_packages)

      # package.json has dependencies "merge": "^1.2.1"
      # yarn audit says merge patched in >=2.1.1, another vul says merge patched in >=1.2.1
      # expected new package.json updates merge to ^1.2.1
      expect(File.exist?(yarn_lock_fixed)).to eq(true)
      expect(File.exist?(package_json_fixed)).to eq(true)
      expect(FileUtils.compare_file(yarn_lock, yarn_lock_fixed)).to eq(true)
      package_json_content = JSON.parse(File.read(package_json))
      package_json_content['dependencies']['merge'] = '^1.2.1'
      package_json_fixed_content = JSON.parse(File.read(package_json_fixed))
      expect(package_json_content).to eq(package_json_fixed_content)

      # update package.json and run salus again, fixed deps will not appear in findings
      FileUtils.cp(package_json_fixed, package_json)
      repo = Salus::Repo.new(repo_path)
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      vulns = JSON.parse(scanner.report.to_h[:info][:stdout])
      vuln_packages = vulns.map { |v| [v['Package'], v['Patched in']] }.sort.uniq
      expected_vuln_packages = [["merge", ">=2.1.1"],
                                ["uglify-js", ">=2.4.24"], ["uglify-js", ">=2.6.0"]]
      expect(vuln_packages).to eq(expected_vuln_packages)
    end

    it 'should update multiple dependencies correctly with direct dependencies' do
      repo_path = 'spec/fixtures/yarn_audit/failure-4'
      yarn_lock = File.join(repo_path, 'yarn.lock')
      package_json = File.join(repo_path, 'package.json')
      yarn_lock_fixed = File.join(repo_path, 'yarn-autofixed.lock')
      package_json_fixed = File.join(repo_path, 'package-autofixed.json')
      [yarn_lock_fixed, package_json_fixed].each do |f|
        File.delete(f) if File.exist?(f)
      end

      repo = Salus::Repo.new(repo_path)
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: { 'auto_fix' => true })
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      vulns = JSON.parse(scanner.report.to_h[:info][:stdout])
      vuln_packages = vulns.map { |v| [v['Package'], v['Patched in']] }.sort.uniq
      expected_vuln_packages = [["dot-prop", ">=4.2.1"],
                                ["lodash", ">=4.17.20"], ["lodash", ">=4.17.21"],
                                ["uglify-js", ">=2.4.24"], ["uglify-js", ">=2.6.0"],
                                ["yargs-parser", ">=13.1.2"]]
      expect(vuln_packages).to eq(expected_vuln_packages)

      # package.json has dependencies "lodash": "4.17.14"
      #                               "dot-prop": "^4.2.0"
      #                               "yargs-parser": "11.1.1
      #                               "uglify-js": "1.2.3""
      # yarn audit says lodash patched in >= 4.17.20 and >= 4.17.21
      #                 dot-prop patched in >= 4.2.1
      #                 yargs-parser patched in >= 13.1.2 (major version update)
      #                 uglify-js patched in >= 2.6.0, 2.4.24 (major version update)
      # expected new package.json updates lodash to 4.17.21 as max(4.17.20, 4.17.21)
      #                                   dot-prop to 4.2.1
      expect(File.exist?(yarn_lock_fixed)).to eq(true)
      expect(File.exist?(package_json_fixed)).to eq(true)
      expect(FileUtils.compare_file(yarn_lock, yarn_lock_fixed)).to eq(true)
      package_json_content = JSON.parse(File.read(package_json))
      package_json_content['dependencies']['lodash'] = '^4.17.21'
      package_json_content['dependencies']['dot-prop'] = '^4.2.1'
      package_json_fixed_content = JSON.parse(File.read(package_json_fixed))
      expect(package_json_content).to eq(package_json_fixed_content)

      # update package.json and run salus again, fixed deps will not appear in findings
      FileUtils.cp(package_json_fixed, package_json)
      repo = Salus::Repo.new(repo_path)
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      vulns = JSON.parse(scanner.report.to_h[:info][:stdout])
      vuln_packages = vulns.map { |v| [v['Package'], v['Patched in']] }.sort.uniq
      expected_vuln_packages = [["uglify-js", ">=2.4.24"], ["uglify-js", ">=2.6.0"],
                                ["yargs-parser", ">=13.1.2"]]
      expect(vuln_packages).to eq(expected_vuln_packages)
    end

    it 'should update indirect dependencies correct' do
      repo_path = 'spec/fixtures/yarn_audit/failure-5'
      yarn_lock = File.join(repo_path, 'yarn.lock')
      package_json = File.join(repo_path, 'package.json')
      yarn_lock_fixed = File.join(repo_path, 'yarn-autofixed.lock')
      package_json_fixed = File.join(repo_path, 'package-autofixed.json')
      [yarn_lock_fixed, package_json_fixed].each do |f|
        File.delete(f) if File.exist?(f)
      end

      repo = Salus::Repo.new(repo_path)
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: { 'auto_fix' => true })
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      vulns = JSON.parse(scanner.report.to_h[:info][:stdout])
      vuln_packages = vulns.map { |v| [v['Package'], v['Patched in']] }.sort.uniq
      expected_vuln_packages = [["node-sass", ">=7.0.0"], ["scss-tokenizer", ">=0.4.3"]]
      expect(vuln_packages).to eq(expected_vuln_packages)

      # package.json has only 1 dependency "node-sass": "6.0.1"
      # yarn audit says node-sass patched >= 7.0.0
      #                 scss-tokenizer patched >= 0.4.3
      expect(File.exist?(yarn_lock_fixed)).to eq(true)
      expect(File.exist?(package_json_fixed)).to eq(true)
      # new yarn.lock has scss-tokenizer patched updated to ^0.4.3
      expected_yarn_lock_fixed = File.join(repo_path, 'expected-yarn-autofixed.lock')
      expect(FileUtils.compare_file(yarn_lock_fixed, expected_yarn_lock_fixed)).to eq(true)

      package_json_content = JSON.parse(File.read(package_json))
      package_json_fixed_content = JSON.parse(File.read(package_json_fixed))
      expect(package_json_content).to eq(package_json_fixed_content)

      # update yarn.lock and run salus again, scss-tokenizer will disappear from vuls
      FileUtils.cp(yarn_lock_fixed, yarn_lock)
      repo = Salus::Repo.new(repo_path)
      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      vulns = JSON.parse(scanner.report.to_h[:info][:stdout])
      vuln_packages = vulns.map { |v| [v['Package'], v['Patched in']] }.sort.uniq
      expected_vuln_packages = [["node-sass", ">=7.0.0"]]
      expect(vuln_packages).to eq(expected_vuln_packages)
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
