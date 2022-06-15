require_relative '../../../spec_helper.rb'

describe Salus::Scanners::Slither do
  describe '#should_run?' do
    it 'should return false in the absence of Solidity files' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      expect(repo.sol_file_present?).to be_falsey

      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return false with .sol files but no package.json/config files' do
      repo = Salus::Repo.new('spec/fixtures/slither/pure-solidity-good')
      expect(repo.sol_file_present?).to be_truthy

      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return false with .sol file, package.json but no config file' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity1')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return false with package.json, config file but no sol file' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity2')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return false with .sol file, truffle config file but no package.json' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity3')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true with .sol file, package.json, and truffle.js' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_truffle_js')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end

    it 'should return true with .sol file, package.json, and truffle.ts' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_truffle_ts')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end

    it 'should return true with .sol file, package.json, and truffle-config.js' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_truffle_config_js')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end

    it 'should return true with .sol file, package.json, and truffle-config.ts' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_truffle_config_ts')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end

    it 'should return true with .sol file, package.json, and hardhat.config.js' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_hardhat_js')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end

    it 'should return true with .sol file, package.json, and hardhat.config.ts' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_hardhat_ts')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#run' do
    it 'should error with npm install fails' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_truffle_bad_config')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      expect(scanner.report.to_h[:logs]).to eq(nil)
      expect(scanner.report.to_h[:info][:stdout]).to eq(nil)
      expect(scanner.report.to_h[:info][:stderr]).to start_with('npm install failed')
    end

    it 'should pass when there are no vulnerabilities' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity-good')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {
                                               "exclude-optimization" => true,
        "exclude-informational" => true
                                             })
      expect(scanner).not_to receive(:report_failure)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should fail when there are vulnerabilities' do
      repo = Salus::Repo.new('spec/fixtures/slither/solidity-bad')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      stdout = scanner.report.to_h[:info][:stdout]
      stdout = JSON.parse(stdout)
      expected_ref_url = Salus::Scanners::Slither::REF_URL_PREFIX + "incorrect-shift"
      expected_vul1 = { "description" => "C.f() (bad-contract.sol#4-8) contains an incorrect "\
                                         "shift operation: a = 8 >> a (bad-contract.sol#6)\n",
                       "location" => "contracts/bad-contract.sol#L4-L8",
                       "check" => "incorrect-shift",
                       "ref_url" => expected_ref_url,
                       "impact" => "High",
                       "confidence" => "High" }
      expected_vul2 = { "description" => "C.g() (bad-contract.sol#10-14) contains an incorrect "\
                                         "shift operation: b = 8 >> b (bad-contract.sol#12)\n",
                       "location" => "contracts/bad-contract.sol#L10-L14",
                       "check" => "incorrect-shift",
                       "ref_url" => expected_ref_url,
                       "impact" => "High",
                       "confidence" => "High" }
      expect(stdout.length).to eq(2)
      expect(stdout).to include(expected_vul1)
      expect(stdout).to include(expected_vul2)
    end

    it 'should report error if solidity code has invalid syntax' do
      repo = Salus::Repo.new('spec/fixtures/slither/no-compile-truffle')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      expect(scanner.report.to_h[:logs]).to eq(nil)
      errs = scanner.report.to_h.fetch(:errors)
      expect(errs.size).to eq(1)
      expect(errs[0][:message]).to include('truffle compile` failed. Can you run it?')
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return solidity' do
        expect(described_class.supported_languages).to eq(['solidity'])
      end
    end
  end

  describe '#config options' do
    context 'filter-paths' do
      let(:repo_dir) { 'spec/fixtures/slither/solidity-bad2' }
      let(:repo) { Salus::Repo.new(repo_dir) }

      it 'should report two vulneraiblities with empty config' do
        scanner = Salus::Scanners::Slither.new(repository: repo, config: {
                                                 "exclude-optimization" => true,
          "exclude-informational" => true
                                               })
        scanner.run

        expect(scanner.report.to_h.fetch(:passed)).to eq(false)
        stdout = scanner.report.to_h[:info][:stdout]
        stdout = JSON.parse(stdout)
        expected_ref_url = Salus::Scanners::Slither::REF_URL_PREFIX + "incorrect-shift"
        expected_vul1 = { "description" => "C.f() (bad-contract1.sol#4-8) contains an incorrect "\
                                           "shift operation: a = 8 >> a (bad-contract1.sol#6)\n",
                          "location" => "contracts/bad-contract1.sol#L4-L8",
                          "check" => "incorrect-shift",
                          "ref_url" => expected_ref_url,
                          "impact" => "High",
                          "confidence" => "High" }
        expected_vul2 = { "description" => "D.g() (bad-contract2.sol#4-8) contains an incorrect "\
                                          "shift operation: b = 8 >> b (bad-contract2.sol#6)\n",
                         "location" => "contracts/bad-contract2.sol#L4-L8",
                         "check" => "incorrect-shift",
                         "ref_url" => expected_ref_url,
                         "impact" => "High",
                         "confidence" => "High" }
        expect(stdout.length).to eq(2)
        expect(stdout).to include(expected_vul1)
        expect(stdout).to include(expected_vul2)
      end

      it 'should apply filter-paths with one path' do
        config_file = "#{repo_dir}/salus_filter_paths_single.yaml"
        config = Salus::Config.new([File.read(config_file)]).scanner_configs['Slither']
        scanner = Salus::Scanners::Slither.new(repository: repo, config: config)
        scanner.run
        expect(scanner.report.to_h.fetch(:passed)).to eq(false)
        stdout = scanner.report.to_h[:info][:stdout]
        stdout = JSON.parse(stdout)
        expected_ref_url = Salus::Scanners::Slither::REF_URL_PREFIX + "incorrect-shift"
        expected_vul = { "description" => "D.g() (bad-contract2.sol#4-8) contains an incorrect "\
                                          "shift operation: b = 8 >> b (bad-contract2.sol#6)\n",
                         "location" => "contracts/bad-contract2.sol#L4-L8",
                         "check" => "incorrect-shift",
                         "ref_url" => expected_ref_url,
                         "impact" => "High",
                         "confidence" => "High" }
        expect(stdout.length).to eq(1)
        expect(stdout[0]).to eq(expected_vul)
      end

      it 'should apply filter-paths if multiple paths' do
        config_file = "#{repo_dir}/salus_filter_paths_multiple.yaml"
        config = Salus::Config.new([File.read(config_file)]).scanner_configs['Slither']
        scanner = Salus::Scanners::Slither.new(repository: repo, config: config)
        scanner.run
        expect(scanner.report.to_h.fetch(:passed)).to eq(true)
      end
    end

    context 'exclude-optimization' do
      let(:repo_dir) { 'spec/fixtures/slither/solidity-bad3' }
      let(:repo) { Salus::Repo.new(repo_dir) }

      it 'should exclude optimization findings when true' do
        config_file = "#{repo_dir}/salus_exclude_optimization.yaml"
        config = Salus::Config.new([File.read(config_file)]).scanner_configs['Slither']
        scanner = Salus::Scanners::Slither.new(repository: repo, config: config)
        scanner.run
        expect(scanner.report.to_h.fetch(:passed)).to eq(true)
      end

      it 'should include optimization findings when false' do
        config_file = "#{repo_dir}/salus_include_optimization.yaml"
        config = Salus::Config.new([File.read(config_file)]).scanner_configs['Slither']
        scanner = Salus::Scanners::Slither.new(repository: repo, config: config)
        scanner.run
        expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      end
    end

    context 'exclude-informational' do
      let(:repo_dir) { 'spec/fixtures/slither/solidity-bad3' }
      let(:repo) { Salus::Repo.new(repo_dir) }

      it 'should exclude informational findings when configured' do
        config_file = "#{repo_dir}/salus_exclude_informational.yaml"
        config = Salus::Config.new([File.read(config_file)]).scanner_configs['Slither']
        scanner = Salus::Scanners::Slither.new(repository: repo, config: config)
        scanner.run
        expect(scanner.report.to_h.fetch(:passed)).to eq(true)
      end

      it 'should include informational findings when configured' do
        config_file = "#{repo_dir}/salus_include_informational.yaml"
        config = Salus::Config.new([File.read(config_file)]).scanner_configs['Slither']
        scanner = Salus::Scanners::Slither.new(repository: repo, config: config)
        scanner.run
        expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      end
    end
  end
end
