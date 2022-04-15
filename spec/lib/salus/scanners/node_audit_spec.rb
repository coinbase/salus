require_relative '../../../spec_helper.rb'

# Make tripples of the class name, snake case name and the class.
NODE_AUDIT_SCANNERS = [
  ['NPMAudit', 'npm_audit', Salus::Scanners::NPMAudit],
  ['YarnAudit', 'yarn_audit', Salus::Scanners::YarnAudit]
].freeze

describe Salus::Scanners::NodeAudit do
  let(:stub_npm_stdout) do
    JSON.parse(File.read('spec/fixtures/npm_audit/success_with_exceptions/stub_stdout.txt'))
  end
  let(:stub_npm_stderr) do
    JSON.parse(File.read('spec/fixtures/npm_audit/success_with_exceptions/stub_stderr.txt'))
  end
  let(:stub_npm_exit_status) { 1 }

  let(:stub_yarn_stdout) do
    File.read('spec/fixtures/yarn_audit/success_with_exceptions/stub_stdout.txt')
  end
  let(:stub_yarn_stdout) do
    File.read('spec/fixtures/yarn_audit/success_with_exceptions/stub_stdout.txt')
  end
  let(:stub_yarn_stdout_latest) do
    File.read('spec/fixtures/yarn_audit/success_with_exceptions/stub_stdout_latest.json')
  end
  let(:stub_yarn_stderr) { "" }
  let(:stub_yarn_exit_status) { 24 }

  # We will test all subclasses of NodeAudit the same for superclass methods like #run.
  # Public methods implemented in the subclass (#should_run?) can be tested in individual files.
  NODE_AUDIT_SCANNERS.each do |scanner|
    klass_str = scanner[0]
    klass_snake_str = scanner[1]
    klass_obj = scanner[2]

    describe "#run #{klass_str}" do
      context 'CVEs in package.json' do
        it 'should fail, recording advisory ids and npm output' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/failure")
          scanner = klass_obj.new(repository: repo, config: {})
          scanner.run

          expect(scanner.report.passed?).to eq(false)
          info = scanner.report.to_h.fetch(:info)
          expect(info.key?(:stdout)).to eq(true)

          if klass_str == 'NPMAudit'
            expect(info[:prod_advisories].size).to eq(2)
            expect(info[:dev_advisories]).to be_empty
            expect(info[:unexcepted_prod_advisories].size).to eq(2)
            expect(info[:exceptions]).to be_empty
            expect(info[:prod_exceptions]).to be_empty
            expect(info[:dev_exceptions]).to be_empty
            expect(info[:useless_exceptions]).to be_empty
          else # YarnAudit
            expect(info[:vulnerabilities].size).to eq(2)
            expect(info[:ignored_cves]).to be_empty
          end
        end

        it 'should fail, recording advisory ids and npm output' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/failure-2")
          scanner = klass_obj.new(repository: repo, config: {})
          scanner.run

          expect(scanner.report.passed?).to eq(false)
          info = scanner.report.to_h.fetch(:info)
          expect(info.key?(:stdout)).to eq(true)
          if klass_str == 'NPMAudit'
            expect(info[:prod_advisories].size).to eq(4)
            expect(info[:dev_advisories]).to be_empty
            expect(info[:unexcepted_prod_advisories].size).to eq(4)
            expect(info[:exceptions]).to be_empty
            expect(info[:prod_exceptions]).to be_empty
            expect(info[:dev_exceptions]).to be_empty
            expect(info[:useless_exceptions]).to be_empty
          else # YarnAudit
            expect(info[:vulnerabilities].size).to eq(4)
            expect(info[:ignored_cves]).to be_empty
          end
        end
      end

      context 'no CVEs in package.json' do
        it 'should record success' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/success")
          scanner = klass_obj.new(repository: repo, config: {})
          scanner.run
          expect(scanner.report.passed?).to eq(true)

          info = scanner.report.to_h.fetch(:info)
          if klass_str == 'NPMAudit'
            expect(info.key?(:stdout)).to eq(true)
            expect(info).to include(
              prod_advisories: [],
              dev_advisories: [],
              unexcepted_prod_advisories: []
            )
          else # YarnAudit
            expect(info.key?(:stdout)).to eq(false)
            expect(info).to include(
              ignored_cves: []
            )
          end
        end
      end

      context 'no CVEs in package.json when ignoring CVEs' do
        it 'should record success and report on the ignored CVEs' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/success_with_exceptions")
          config_file = YAML.load_file(
            "spec/fixtures/#{klass_snake_str}/success_with_exceptions/salus.yaml"
          )
          scanner = klass_obj.new(
            repository: repo, config: config_file['scanner_configs'][klass_str]
          )

          if klass_str == "NPMAudit"
            stub_stdout = stub_npm_stdout
            stub_stderr = stub_npm_stderr
            stub_status = stub_npm_exit_status
          elsif klass_str == "YarnAudit"
            stub_stdout = stub_yarn_stdout
            stub_stderr = stub_yarn_stderr
            stub_status = stub_yarn_exit_status
          end

          process_status = ProcessStatusDouble.new(stub_status)
          stub_shell_return = Salus::ShellResult.new(stub_stdout, stub_stderr, process_status)
          allow(scanner).to receive(:version).and_return('1.22.0') if klass_str == 'YarnAudit'
          allow(scanner).to receive(:run_shell).and_return(stub_shell_return)

          scanner.run

          expect(scanner.report.passed?).to eq(true)
          info = scanner.report.to_h.fetch(:info)
          if klass_str == 'NPMAudit'
            expect(info.key?(:stdout)).to eq(true)
            expect(info).to include(
              prod_advisories: %w[1006708 1006709],
              dev_advisories: [],
              unexcepted_prod_advisories: [],
              exceptions: %w[1006708 1006709],
              prod_exceptions: %w[1006708 1006709],
              dev_exceptions: [],
              useless_exceptions: []
            )
          else # YarnAudit
            # YarnAudit no longer displays vulns that have been whitelisted
            expect(info.key?(:stdout)).to eq(false)
            expect(info).to include(
              ignored_cves: [1_006_708, 1_006_709],
              vulnerabilities: [1_006_708, 1_006_709]
            )
          end
        end
      end

      context 'exception expirations' do
        before(:each) do
          allow(Date).to receive(:today).and_return Date.new(2021, 12, 31)
        end

        it 'should record success and when expiration is future' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/success_with_exceptions")
          config_file = YAML.load_file(
            "spec/fixtures/#{klass_snake_str}/success_with_exceptions/salus-non-expired.yaml"
          )
          scanner = klass_obj.new(
            repository: repo, config: config_file['scanner_configs'][klass_str]
          )

          if klass_str == "NPMAudit"
            stub_stdout = stub_npm_stdout
            stub_stderr = stub_npm_stderr
            stub_status = stub_npm_exit_status
          elsif klass_str == "YarnAudit"
            stub_stdout = stub_yarn_stdout
            stub_stderr = stub_yarn_stderr
            stub_status = stub_yarn_exit_status
          end

          process_status = ProcessStatusDouble.new(stub_status)
          stub_shell_return = Salus::ShellResult.new(stub_stdout, stub_stderr, process_status)
          allow(scanner).to receive(:version).and_return('1.22.0') if klass_str == 'YarnAudit'
          allow(scanner).to receive(:run_shell).and_return(stub_shell_return)
          scanner.run
          expect(scanner.report.passed?).to eq(true)
        end

        it 'should record success and when expiration is future for yarn v3' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/success_with_exceptions")
          config_file = YAML.load_file(
            "spec/fixtures/#{klass_snake_str}/success_with_exceptions/salus-non-expired.yaml"
          )
          scanner = klass_obj.new(
            repository: repo, config: config_file['scanner_configs'][klass_str]
          )

          if klass_str == "YarnAudit"
            stub_stdout = stub_yarn_stdout_latest
            stub_stderr = stub_yarn_stderr
            stub_status = stub_yarn_exit_status

            process_status = ProcessStatusDouble.new(stub_status)
            stub_shell_return_latest = Salus::ShellResult.new(stub_stdout, stub_stderr,
                                                              process_status)
            allow(scanner).to receive(:version).and_return('3.1.0') if klass_str == 'YarnAudit'
            allow(scanner).to receive(:run_shell).and_return(stub_shell_return_latest)

            scanner.run
            expect(scanner.report.passed?).to eq(true)
          end
        end

        it 'should record failure and when expiration is past' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/success_with_exceptions")
          config_file = YAML.load_file(
            "spec/fixtures/#{klass_snake_str}/success_with_exceptions/salus-expired.yaml"
          )
          scanner = klass_obj.new(
            repository: repo, config: config_file['scanner_configs'][klass_str]
          )
          scanner.run

          expect(scanner.report.passed?).to eq(false)
        end

        it 'should support integer ids' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/success_with_exceptions")
          config_file = YAML.load_file(
            "spec/fixtures/#{klass_snake_str}/success_with_exceptions/salus-integer-ids.yaml"
          )
          scanner = klass_obj.new(
            repository: repo, config: config_file['scanner_configs'][klass_str]
          )

          if klass_str == "NPMAudit"
            stub_stdout = stub_npm_stdout
            stub_stderr = stub_npm_stderr
            stub_status = stub_npm_exit_status
          elsif klass_str == "YarnAudit"
            stub_stdout = stub_yarn_stdout
            stub_stderr = stub_yarn_stderr
            stub_status = stub_yarn_exit_status
          end

          process_status = ProcessStatusDouble.new(stub_status)
          stub_shell_return = Salus::ShellResult.new(stub_stdout, stub_stderr, process_status)
          allow(scanner).to receive(:version).and_return('1.22.0') if klass_str == 'YarnAudit'
          allow(scanner).to receive(:run_shell).and_return(stub_shell_return)

          scanner.run
          expect(scanner.report.passed?).to eq(true)
        end

        it 'should support integer ids for yarn v3' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/success_with_exceptions")
          config_file = YAML.load_file(
            "spec/fixtures/#{klass_snake_str}/success_with_exceptions/salus-integer-ids.yaml"
          )
          scanner = klass_obj.new(
            repository: repo, config: config_file['scanner_configs'][klass_str]
          )

          if klass_str == "YarnAudit"
            stub_stdout = stub_yarn_stdout_latest
            stub_stderr = stub_yarn_stderr
            stub_status = stub_yarn_exit_status

            process_status = ProcessStatusDouble.new(stub_status)
            stub_shell_return_latest = Salus::ShellResult.new(stub_stdout, stub_stderr,
                                                              process_status)
            allow(scanner).to receive(:version).and_return('3.1.0') if klass_str == 'YarnAudit'
            allow(scanner).to receive(:run_shell).and_return(stub_shell_return_latest)

            scanner.run

            expect(scanner.report.passed?).to eq(true)
          end
        end
      end
    end
  end
end
