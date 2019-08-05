require_relative '../../../spec_helper.rb'

# Make tripples of the class name, snake case name and the class.
NODE_AUDIT_SCANNERS = [
  ['NPMAudit', 'npm_audit', Salus::Scanners::NPMAudit],
  ['YarnAudit', 'yarn_audit', Salus::Scanners::YarnAudit]
].freeze

describe Salus::Scanners::NodeAudit do
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
          expect(info).to include(
            prod_advisories: %w[39 48],
            dev_advisories: [],
            unexcepted_prod_advisories: %w[39 48],
            exceptions: [],
            prod_exceptions: [],
            dev_exceptions: [],
            useless_exceptions: []
          )
        end

        it 'should fail, recording advisory ids and npm output' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/failure-2")
          scanner = klass_obj.new(repository: repo, config: {})
          scanner.run

          expect(scanner.report.passed?).to eq(false)
          info = scanner.report.to_h.fetch(:info)
          expect(info.key?(:stdout)).to eq(true)
          expect(info).to include(
            prod_advisories: %w[39 48 722],
            dev_advisories: [],
            unexcepted_prod_advisories: %w[39 48 722],
            exceptions: [],
            prod_exceptions: [],
            dev_exceptions: [],
            useless_exceptions: []
          )
        end
      end

      context 'no CVEs in package.json' do
        it 'should record success' do
          repo = Salus::Repo.new("spec/fixtures/#{klass_snake_str}/success")
          scanner = klass_obj.new(repository: repo, config: {})
          scanner.run
          expect(scanner.report.passed?).to eq(true)

          info = scanner.report.to_h.fetch(:info)
          expect(info.key?(:stdout)).to eq(true)
          expect(info).to include(
            prod_advisories: [],
            dev_advisories: [],
            unexcepted_prod_advisories: []
          )
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
          expect(info.key?(:stdout)).to eq(true)
          expect(info).to include(
            prod_advisories: %w[39 48],
            dev_advisories: [],
            unexcepted_prod_advisories: [],
            exceptions: %w[39 48],
            prod_exceptions: %w[39 48],
            dev_exceptions: [],
            useless_exceptions: []
          )
        end
      end
    end
  end
end
