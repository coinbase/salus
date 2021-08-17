require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportPythonModules do
  describe '#should_run?' do
    it 'should return false in the absence of requirements.txt' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportPythonModules.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if requirements.txt is present' do
      repo = Salus::Repo.new('spec/fixtures/python/requirements_unpinned')
      scanner = Salus::Scanners::ReportPythonModules.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  it 'should report modules from requirements.txt' do
    repo = Salus::Repo.new('spec/fixtures/python/requirements_unpinned')
    scanner = Salus::Scanners::ReportPythonModules.new(repository: repo, config: {})

    scanner.run

    dependencies = scanner.report.to_h.fetch(:info).fetch(:dependencies)

    expect(dependencies).to match_array(
      [
        {
          dependency_file: 'requirements.txt',
          name: 'requests',
          version: '>=2.5',
          type: 'pypi'
        },
        {
          dependency_file: 'requirements.txt',
          name: 'six',
          version: '>=1.9',
          type: 'pypi'
        },
        {
          dependency_file: 'requirements.txt',
          name: 'pycryptodome',
          version: '>=3.4.11',
          type: 'pypi'
        }
      ]
    )
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::ReportPythonModules.new(repository: repo, config: {})
        expect(scanner.version).to eq('')
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::ReportPythonModules.supported_languages
        expect(langs).to eq(['python'])
      end
    end
  end
end
