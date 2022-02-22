require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportGradleDeps do
  describe '#should_run?' do
    it 'should return false in the absence of build.gradle' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportGradleDeps.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if build.gradle is present' do
      repo = Salus::Repo.new('spec/fixtures/report_gradle_deps/normal')
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
    repo = Salus::Repo.new('spec/fixtures/report_gradle_deps/normal')
    scanner = Salus::Scanners::ReportGradleDeps.new(repository: repo, config: {})

    scanner.run
    dependencies = scanner.report.to_h.fetch(:info).fetch(:dependencies)

    expect(dependencies.size).to eq(61)
    expect(dependencies).to include(
      {
        dependency_file: "build.gradle",
        name: "org.apache.kafka/connect-transforms",
        type: "gradle",
        version: "2.6.2"
      },
      {
        dependency_file: "build.gradle",
        name: "org.apache.kafka/connect-api",
        type: "gradle",
        version: "2.6.2"
      },
      {
        dependency_file: "build.gradle",
        name: "org.apache.kafka/kafka-clients",
        type: "gradle",
        version: "2.6.2"
      }
    )
  end

  it 'should report an error when a file with no parseable dependencies is found' do
    repo = Salus::Repo.new('spec/fixtures/report_gradle_deps/bad_gradle_cant_parse')
    scanner = Salus::Scanners::ReportGradleDeps.new(repository: repo, config: {})

    scanner.run

    errs = scanner.report.to_h.fetch(:errors)
    expect(errs.size).to eq(1)
    # Gradle includes time values (which won't be consistent) and a lot of whitespace and text
    # in this message, so the following line asserts String inclusion rather than equality
    expect(errs[0][:message].include?("
Could not compile build file "\
"'/home/spec/fixtures/report_gradle_deps/bad_gradle_cant_parse/build.gradle'"))
  end
end
