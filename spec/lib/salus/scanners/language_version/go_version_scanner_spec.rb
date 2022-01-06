require_relative '../../../../spec_helper.rb'

describe Salus::Scanners::LanguageVersion::GoVersionScanner do
  describe '#run' do
    context 'with non-go project' do
      it 'should record error to scanner report' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        scanner = described_class.new(repository: repo, config: {})

        expect(scanner.should_run?).to eq(false)

        scanner.run

        expect(scanner.report.passed?).to eq(false)

        msg = scanner.report.to_h.fetch(:errors)[0][:message]
        expect(msg).to include('Please supply the path to a go application')
      end
    end

    context 'with go project' do
      let(:path_str) { "../../../../../spec/fixtures/language_version/go_version_scanner" }
      let(:fixture_path) { File.expand_path(path_str, __dir__) }

      context 'for valid version' do
        # go 1.16 vs config of min_version: '1.15.0', max_version: '1.20.3'
        it 'should check the version successfully if the version is within the range' do
          repo = Salus::Repo.new(File.join(fixture_path, 'valid_version'))

          config_file = YAML.load_file(File.join(fixture_path, 'valid_version/salus.yml'))
          scanner = described_class.new(
            repository: repo, config: config_file['scanner_configs']['GoVersionScanner']
          )

          expect(scanner.should_run?).to eq(true)

          scanner.run

          expect(scanner.report.passed?).to eq(true)
        end

        # go 1.16 vs config of min_version: '1.16.0', max_version: '1.20.3'
        it 'should check the version successfully if the version is min_version' do
          repo = Salus::Repo.new(File.join(fixture_path, 'valid_version'))

          config_file = YAML.load_file(File.join(fixture_path, 'valid_version/salus.yml'))
          scanner = described_class.new(
            repository: repo, config: config_file['scanner_configs']['GoVersionScanner']
          )

          expect(scanner.should_run?).to eq(true)

          scanner.run

          expect(scanner.report.passed?).to eq(true)
        end
      end

      context 'for invalid version' do
        # go 1.14 vs config of min_version: '1.15.0', max_version: '1.20.3'
        it 'should record an error if go version is less than min_version' do
          repo = Salus::Repo.new(File.join(fixture_path, 'invalid_version_1'))

          config_file = YAML.load_file(File.join(fixture_path, 'invalid_version_1/salus.yml'))
          scanner = described_class.new(
            repository: repo, config: config_file['scanner_configs']['GoVersionScanner']
          )

          expect(scanner.should_run?).to eq(true)

          scanner.run

          expect(scanner.report.passed?).to eq(false)
          msg = "Repository language version (1.14) " \
                       "is less than minimum configured version (1.15.0)"

          expect(scanner.report.to_h.fetch(:errors).first.fetch(:message)).to include(msg)
        end

        # go 1.21 vs config of min_version: '1.15.0', max_version: '1.20.3'
        it 'should record an error if go version is greater than max_version' do
          repo = Salus::Repo.new(File.join(fixture_path, 'invalid_version_2'))

          config_file = YAML.load_file(File.join(fixture_path, 'invalid_version_2/salus.yml'))
          scanner = described_class.new(
            repository: repo, config: config_file['scanner_configs']['GoVersionScanner']
          )

          expect(scanner.should_run?).to eq(true)

          scanner.run

          expect(scanner.report.passed?).to eq(false)
          msg = "Repository language version (1.21) " \
                       "is greater than maximum configured version (1.20.3)"

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
