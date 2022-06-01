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

    it 'should return true with .sol file, package.json, and truffle config' do
      # has package.json and truffle.js
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_truffle_js')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)

      # has package.json and truffle.ts
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_truffle_ts')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)

      # has package.json and truffle-config.js
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_truffle_config_js')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)

      # has package.json and truffle-config.ts
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_truffle_config_ts')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end

    it 'should return true with .sol file, package.json, and hardhat config' do
      # has package.json and hardhat.config.js
      repo = Salus::Repo.new('spec/fixtures/slither/solidity_hardhat_js')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)

      # has package.json and hardhat.config.ts
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
      repo = Salus::Repo.new('spec/fixtures/slither/pure-solidity-good')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner).not_to receive(:report_failure)
      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(true)
    end

    it 'should fail when there are vulnerabilities in a pure Solidity project' do
      repo = Salus::Repo.new('spec/fixtures/slither/pure-solidity-bad')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner).to receive(:report_failure).and_call_original
      scanner.run

      logs = scanner.report.to_h.fetch(:logs)
      json_logs = JSON.parse(logs)

      expect(json_logs['results']['detectors'].length).to eq(1)
      expect(json_logs['results']['detectors'][0]['description']).to eq("C.f() "\
      "(bad-contract.sol#4-8) contains an incorrect shift operation: a = 8 >> a "\
      "(bad-contract.sol#6)\n")

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should fail when there are vulnerabilities in a Solidity project with NPM dependencies' do
      repo = Salus::Repo.new('spec/fixtures/slither/npm-dep-management')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})
      expect(scanner).to receive(:report_failure).and_call_original
      scanner.run

      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
    end

    it 'should report error if there were issues running slither' do
      repo = Salus::Repo.new('spec/fixtures/slither/no-compile')
      scanner = Salus::Scanners::Slither.new(repository: repo, config: {})

      expect(scanner).to receive(:report_failure).and_call_original
      expect(scanner).not_to receive(:report_stdout)
      expect(scanner).not_to receive(:log)
      expect(scanner).to receive(:report_error).and_call_original

      # The error logged to stderr is an extremely long stack trace that's saturated
      # with whitespace. This makes it cumbersome to have in this test
      expect(scanner).to receive(:report_stderr)

      scanner.run
      expect(scanner.report.to_h.fetch(:passed)).to eq(false)
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
        langs = Salus::Scanners::Slither.supported_languages
        expect(langs).to eq(['solidity'])
      end
    end
  end
end
