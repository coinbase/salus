require_relative '../../../spec_helper.rb'

describe Salus::Scanners::MisnamedConfig do
  describe '#run' do
    context 'repo containing a correct salus.yaml configuration file' do
      it 'should be a simple pass' do
        repo = Salus::Repo.new('spec/fixtures/misnamed_config/correct_config')
        scanner = Salus::Scanners::MisnamedConfig.new(repository: repo, config: {})
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end
    end

    context 'repo containing a misnamed salus.yml configuration file' do
      it 'should fail' do
        repo = Salus::Repo.new('spec/fixtures/misnamed_config/misnamed_config')
        scanner = Salus::Scanners::MisnamedConfig.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        scan_report = scanner.report
        errors = scan_report.to_h.fetch(:errors)

        expect(errors.length).to eq(1)
        expect(errors[0][:message]).to eq(
          'A local file "salus.yml" was detected in the provided repository. The '\
          'correct configuration file name is "salus.yaml".'
        )
      end
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::MisnamedConfig.new(repository: repo, config: {})
        expect(scanner.version).to eq('')
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::MisnamedConfig.supported_languages
        expect(langs).to eq(['*'])
      end
    end
  end
end
