require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportPodfileLock do
  describe '#should_run?' do
    it 'should return false in the absence of Podfile.lock' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportPodfileLock.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if Podfile.lock is present' do
      repo = Salus::Repo.new('spec/fixtures/report_podfile_lock/normal')
      scanner = Salus::Scanners::ReportPodfileLock.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::ReportPodfileLock.new(repository: repo, config: {})
        expect(scanner.version).to eq('')
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::ReportPodfileLock.supported_languages
        expect(langs).to eq(%w[swift objective-c])
      end
    end
  end

  it 'should report modules from Podfile.lock' do
    repo = Salus::Repo.new('spec/fixtures/report_podfile_lock/normal')
    scanner = Salus::Scanners::ReportPodfileLock.new(repository: repo, config: {})

    scanner.run

    dependencies = scanner.report.to_h.fetch(:info).fetch(:dependencies)

    expect(dependencies).to match_array(
      [
        {
          dependency_file: 'Podfile.lock',
            name: 'boost-for-react-native',
            version: '1.63.0',
            type: 'cocoapods'
        },
        {
          dependency_file: 'Podfile.lock',
        name: 'CocoaAsyncSocket',
        version: '7.6.5',
        type: 'cocoapods'
        },
        {
          dependency_file: 'Podfile.lock',
            name: 'Flipper',
            version: '0.87.0',
            type: 'cocoapods'
        }
      ]
    )
  end

  it 'should report an error when an unparseable file is found' do
    repo = Salus::Repo.new('spec/fixtures/report_podfile_lock/bad_podfile_cant_parse')
    scanner = Salus::Scanners::ReportPodfileLock.new(repository: repo, config: {})

    scanner.run

    errs = scanner.report.to_h.fetch(:errors)
    expect(errs.size).to eq(1)
    expect(errs[0][:message]).to eq('Unable to parse Podfile.lock file
')
  end

  it 'should report an error when an unparseable file is found' do
    repo = Salus::Repo.new('spec/fixtures/report_podfile_lock/empty_podfile_values')
    scanner = Salus::Scanners::ReportPodfileLock.new(repository: repo, config: {})

    scanner.run

    errs = scanner.report.to_h.fetch(:errors)
    expect(errs.size).to eq(1)
    expect(errs[0][:message]).to eq('No dependencies found in Podfile.lock!
')
  end
end
