require_relative '../../../../spec_helper.rb'

describe Salus::Scanners::LanguageVersion::RubyVersionScanner do
  describe '#run' do
    context 'with non-ruby project' do
      it 'should record error to scanner report' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        scanner = described_class.new(repository: repo, config: {})

        expect(scanner.should_run?).to eq(false)

        scanner.run

        expect(scanner.report.passed?).to eq(false)

        msg = scanner.report.to_h.fetch(:errors)[0][:message]
        expect(msg).to include('Please supply the path to a ruby application')
      end
    end

    context 'with ruby project' do
      let(:path_str) { "../../../../../spec/fixtures/language_version/ruby_version_scanner" }
      let(:fixture_path) { File.expand_path(path_str, __dir__) }

      it 'should pass successfully for valid version' do
        # ruby 2.7.2 vs config of min_version: '2.6.0', max_version: '2.7.6'
        repo = Salus::Repo.new(File.join(fixture_path, 'valid_version'))

        config_file = YAML.load_file(File.join(fixture_path, 'valid_version/salus.yml'))
        scanner = described_class.new(
          repository: repo, config: config_file['scanner_configs']['RubyVersionScanner']
        )

        expect(scanner.should_run?).to eq(true)

        scanner.run

        expect(scanner.report.passed?).to eq(true)
      end

      context 'for invalid version' do
        # ruby 2.1.0 vs config of min_version: '2.6.0', max_version: '2.7.6'
        it 'should record an error if ruby version is less than min_version' do
          repo = Salus::Repo.new(File.join(fixture_path, 'invalid_version_1'))

          config_file = YAML.load_file(File.join(fixture_path, 'invalid_version_1/salus.yml'))
          scanner = described_class.new(
            repository: repo, config: config_file['scanner_configs']['RubyVersionScanner']
          )

          expect(scanner.should_run?).to eq(true)

          scanner.run

          expect(scanner.report.passed?).to eq(false)
          msg = "Repository language version (2.1.0) " \
                       "is less than minimum configured version (2.6.0)"

          expect(scanner.report.to_h.fetch(:errors).first.fetch(:message)).to include(msg)
        end

        # ruby 2.8.4 vs config of min_version: '2.6.0', max_version: '2.7.6'
        it 'should record an error if ruby version is greater than max_version' do
          repo = Salus::Repo.new(File.join(fixture_path, 'invalid_version_2'))

          config_file = YAML.load_file(File.join(fixture_path, 'invalid_version_2/salus.yml'))
          scanner = described_class.new(
            repository: repo, config: config_file['scanner_configs']['RubyVersionScanner']
          )

          expect(scanner.should_run?).to eq(true)

          scanner.run

          expect(scanner.report.passed?).to eq(false)
          msg = "Repository language version (2.8.4) " \
                       "is greater than maximum configured version (2.7.6)"

          expect(scanner.report.to_h.fetch(:errors).first.fetch(:message)).to include(msg)
        end

        # ruby 2.5.4 vs config of min_version: '2.7.3', max_version: '2.8.6'
        it 'should record an error if only Gemfile is present' do
          repo = Salus::Repo.new(File.join(fixture_path, 'invalid_version_3'))

          config_file = YAML.load_file(File.join(fixture_path, 'invalid_version_3/salus.yml'))
          scanner = described_class.new(
            repository: repo, config: config_file['scanner_configs']['RubyVersionScanner']
          )

          expect(scanner.should_run?).to eq(true)

          scanner.run

          expect(scanner.report.passed?).to eq(false)
          msg = "Repository language version (2.5.4) " \
                       "is less than minimum configured version (2.7.3)"

          expect(scanner.report.to_h.fetch(:errors).first.fetch(:message)).to include(msg)
        end

        # ruby 2.7.2p83 vs config of min_version: '2.7.3', max_version: '2.8.6'
        it 'should record an error if only Gemfile is present' do
          repo = Salus::Repo.new(File.join(fixture_path, 'invalid_version_4'))

          config_file = YAML.load_file(File.join(fixture_path, 'invalid_version_4/salus.yml'))
          scanner = described_class.new(
            repository: repo, config: config_file['scanner_configs']['RubyVersionScanner']
          )

          expect(scanner.should_run?).to eq(true)

          scanner.run

          expect(scanner.report.passed?).to eq(false)
          msg = "Repository language version (2.7.2p83) " \
                       "is less than minimum configured version (2.7.3)"

          expect(scanner.report.to_h.fetch(:errors).first.fetch(:message)).to include(msg)
        end

        it 'should not run if min_version and max_version are not configured' do
          repo = Salus::Repo.new(File.join(fixture_path, 'valid_version'))
          scanner = described_class.new(repository: repo, config: {})
          expect(scanner.should_run?).to eq(false)
        end
      end
    end
  end
end
