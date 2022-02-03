require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportGradleDeps, :focus do
  describe '#should_run?' do
    it 'should return false in the absence of build.gradle' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportGradleDeps.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if build.gradle is present' do
      repo = Salus::Repo.new('spec/fixtures/report_build_gradle/normal')
      scanner = Salus::Scanners::ReportGradleDeps.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::ReportGradleDeps.new(repository: repo, config: {})
        expect(scanner.version).to eq('')
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::ReportGradleDeps.supported_languages
        expect(langs).to eq(['java'])
      end
    end
  end

  it 'should report modules from build.gradle' do
    repo = Salus::Repo.new('spec/fixtures/report_build_gradle/normal')
    scanner = Salus::Scanners::ReportGradleDeps.new(repository: repo, config: {})

    scanner.run

    dependencies = scanner.report.to_h.fetch(:info).fetch(:dependencies)

    expect(dependencies).to match_array(
      [
        {
          dependency_file: 'build.gradle',
            name: 'com.android.tools.build/gradle',
            version: '3.5.3',
            type: 'gradle'
        },
        {
          dependency_file: 'build.gradle',
        name: 'com.facebook.react/react-native',
        version: '+',
        type: 'gradle'
        },
        {
          dependency_file: 'build.gradle',
            name: 'androidx.work/work-runtime',
            version: '2.4.0',
            type: 'gradle'
        },
        {
          dependency_file: 'build.gradle',
            name: 'androidx.security/security-crypto',
            version: '1.0.0',
            type: 'gradle'
        },
        {
          dependency_file: 'build.gradle',
            name: 'com.google.code.gson/gson',
            version: '2.8.8',
            type: 'gradle'
        }
      ]
    )
  end

  it 'should report an error when a file with no parseable dependencies is found' do
    repo = Salus::Repo.new('spec/fixtures/report_build_gradle/bad_gradle_cant_parse')
    scanner = Salus::Scanners::ReportGradleDeps.new(repository: repo, config: {})

    scanner.run

    errs = scanner.report.to_h.fetch(:errors)
    expect(errs.size).to eq(1)
    expect(errs[0][:message]).to eq('Could not parse dependencies from build.gradle file
')
  end
end
