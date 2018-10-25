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
          type: 'python_requirement'
        },
        {
          dependency_file: 'requirements.txt',
          name: 'six',
          version: '>=1.9',
          type: 'python_requirement'
        },
        {
          dependency_file: 'requirements.txt',
          name: 'pycryptodome',
          version: '>=3.4.11',
          type: 'python_requirement'
        }
      ]
    )
  end
end
