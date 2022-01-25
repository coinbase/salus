require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportPomXml do
  describe '#should_run?' do
    it 'should return false in the absence of pom.xml' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportPomXml.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if pom.xml is present' do
      repo = Salus::Repo.new('spec/fixtures/report_pom_xml')
      scanner = Salus::Scanners::ReportPomXml.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  it 'should report modules from pom.xml' do
    repo = Salus::Repo.new('spec/fixtures/report_pom_xml')
    scanner = Salus::Scanners::ReportPomXml.new(repository: repo, config: {})

    scanner.run

    dependencies = scanner.report.to_h.fetch(:info).fetch(:dependencies)

    expect(dependencies).to match_array(
      [
        {
          dependency_file: 'pom.xml',
            name: 'org.apache.kafka.connect-api',
            version: 'unknown',
            type: 'maven'
        },
        {
          dependency_file: 'pom.xml',
        name: 'org.apache.kafka.connect-json',
        version: 'unknown',
        type: 'maven'
        },
        {
          dependency_file: 'pom.xml',
            name: 'junit.junit',
            version: '1.1.1',
            type: 'maven'
        }
      ]
    )
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::ReportPomXml.new(repository: repo, config: {})
        expect(scanner.version).to eq('')
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::ReportPomXml.supported_languages
        expect(langs).to eq(['java'])
      end
    end
  end
end
