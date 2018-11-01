require_relative '../../../spec_helper.rb'

describe Salus::Scanners::Brakeman do
  describe '#run' do
    context 'non-rails project' do
      it 'should record the STDERR of brakeman' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})

        expect(scanner.should_run?).to eq(false)

        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:stderr]).to include('Please supply the path to a Rails application')
      end
    end

    context 'rails project with vulnerabilities' do
      it 'should record failure and record the STDOUT from brakeman' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/vulnerable_rails_app')

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:stdout]).not_to eq(nil)
        expect(info[:stdout]).not_to eq("")
        expect(info[:brakeman_report][:warnings][0][:warning_type]).to eq('Dangerous Eval')
      end
    end
  end

  describe '#should_run?' do
    context 'no Gemfile nor Rails gem' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.gemfile_present?).to eq(false)

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'Gemfile present but no rails gem' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/ruby_app')
        expect(repo.gemfile_present?).to eq(true)
        expect(repo.gemfile).not_to match(/('|")rails('|")/)

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'Gemfile present with rails gem' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/safe_rails_app')
        expect(repo.gemfile_present?).to eq(true)
        expect(repo.gemfile).to match(/('|")rails('|")/)

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(true)
      end
    end
  end
end
