require_relative '../../../spec_helper.rb'

# Make tripples of the class name, snake case name and the class.
NODE_AUDIT_SCANNERS = [
  ['NPMAudit', 'npm_audit', Salus::Scanners::NPMAudit],
  ['YarnAudit', 'yarn_audit', Salus::Scanners::YarnAudit]
].freeze

describe Salus::Scanners::NodeAudit do
  let(:vuln_1) { 1_004_707 } # was 39
  let(:vuln_2) { 1_004_708 } # was 48
  let(:vuln_3) { 1_002_899 } # was 722
  let(:vuln_4) { 1_004_565 } # was 1666

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
            expect(info).to include(
              prod_advisories: [vuln_1.to_s, vuln_2.to_s],
              dev_advisories: [],
              unexcepted_prod_advisories: [vuln_1.to_s, vuln_2.to_s],
              exceptions: [],
              prod_exceptions: [],
              dev_exceptions: [],
              useless_exceptions: []
            )
          else # YarnAudit
            expect(info).to include(
              vulnerabilities: [vuln_1, vuln_2],
              ignored_cves: []
            )
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
            expect(info).to include(
              prod_advisories: [vuln_3.to_s, vuln_4.to_s, vuln_1.to_s, vuln_2.to_s],
              dev_advisories: [],
              unexcepted_prod_advisories: [vuln_3.to_s, vuln_4.to_s, vuln_1.to_s, vuln_2.to_s],
              exceptions: [],
              prod_exceptions: [],
              dev_exceptions: [],
              useless_exceptions: []
            )
          else # YarnAudit
            expect(info).to include(
              vulnerabilities: [vuln_3, vuln_4, vuln_1, vuln_2],
              ignored_cves: []
            )
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
          scanner.run

          expect(scanner.report.passed?).to eq(true)
          info = scanner.report.to_h.fetch(:info)
          if klass_str == 'NPMAudit'
            expect(info.key?(:stdout)).to eq(true)
            expect(info).to include(
              prod_advisories: [vuln_1.to_s, vuln_2.to_s],
              dev_advisories: [],
              unexcepted_prod_advisories: [],
              exceptions: [vuln_1.to_s, vuln_2.to_s],
              prod_exceptions: [vuln_1.to_s, vuln_2.to_s],
              dev_exceptions: [],
              useless_exceptions: []
            )
          else # YarnAudit
            # YarnAudit no longer displays vulns that have been whitelisted
            expect(info.key?(:stdout)).to eq(false)
            expect(info).to include(
              ignored_cves: [vuln_1, vuln_2],
              vulnerabilities: [vuln_1, vuln_2]
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
          scanner.run
          expect(scanner.report.passed?).to eq(true)
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
          scanner.run
          expect(scanner.report.passed?).to eq(true)
        end
      end
    end
  end
end
