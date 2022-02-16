require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportSwiftDeps do
  describe '#should_run?' do
    it 'should return false in the absence of Package.resolved' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportSwiftDeps.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if Package.resolved is present' do
      repo = Salus::Repo.new('spec/fixtures/report_swift_deps/normal')
      scanner = Salus::Scanners::ReportSwiftDeps.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::ReportSwiftDeps.new(repository: repo, config: {})
        expect(scanner.version).to eq('')
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::ReportSwiftDeps.supported_languages
        expect(langs).to eq(%w[swift])
      end
    end
  end

  it 'should report modules from Package.resolved' do
    repo = Salus::Repo.new('spec/fixtures/report_swift_deps/normal')
    scanner = Salus::Scanners::ReportSwiftDeps.new(repository: repo, config: {})

    scanner.run

    dependencies = scanner.report.to_h.fetch(:info).fetch(:dependencies)

    expect(dependencies).to match_array(
      [
        {
          dependency_file: 'Package.resolved',
            name: 'Cryptor',
            version: '2.0.1',
            type: 'swift',
            source: 'https://github.com/Kitura/BlueCryptor.git'
        },
        {
          dependency_file: 'Package.resolved',
        name: 'CryptorECC',
        version: '1.2.200',
        type: 'swift',
        source: 'https://github.com/Kitura/BlueECC.git'
        },
        {
          dependency_file: 'Package.resolved',
            name: 'CryptorRSA',
            version: '1.0.201',
            type: 'swift',
            source: 'https://github.com/Kitura/BlueRSA.git'
        }
      ]
    )
  end

  it 'should report an error when an unparseable file is found' do
    repo = Salus::Repo.new('spec/fixtures/report_swift_deps/bad_file_cant_parse')
    scanner = Salus::Scanners::ReportSwiftDeps.new(repository: repo, config: {})

    scanner.run

    errs = scanner.report.to_h.fetch(:errors)
    expect(errs.size).to eq(1)
    expect(errs[0][:message]).to eq('Unable to parse Package.resolved JSON
')
  end
end
