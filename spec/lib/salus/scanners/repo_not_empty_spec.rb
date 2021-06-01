require_relative '../../../spec_helper.rb'

describe Salus::Scanners::RepoNotEmpty do
  describe '#run' do
    context 'non blank directory' do
      it 'should be a simple pass' do
        repo = Salus::Repo.new('spec/fixtures/repo_not_empty/non_blank')
        scanner = Salus::Scanners::RepoNotEmpty.new(repository: repo, config: {})
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end
    end

    context 'blank directory' do
      let(:blank_dir) { 'spec/fixtures/repo_not_empty/blank' }

      it 'should be a simple pass' do
        Dir.mktmpdir(blank_dir) do
          expect(Dir["#{blank_dir}/*"]).to be_empty

          repo = Salus::Repo.new(blank_dir)
          scanner = Salus::Scanners::RepoNotEmpty.new(repository: repo, config: {})
          scanner.run

          scan_report = scanner.report
          errors = scan_report.to_h.fetch(:errors)

          expect(scan_report.passed?).to eq(false)
          expect(errors.length).to eq(1)
          expect(errors[0][:message]).to include('may indicate misconfiguration')
        end
      end
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::RepoNotEmpty.new(repository: repo, config: {})
        expect(scanner.version).to eq('')
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::RepoNotEmpty.supported_languages
        expect(langs).to eq(['*'])
      end
    end
  end
end
