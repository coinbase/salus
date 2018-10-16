require_relative '../../../spec_helper.rb'

describe Salus::Scanners::Brakeman do
  let(:blank_config) { {} }
  let(:report) { Salus::Report.new }
  let(:scan_report) { json_report['scans']['Brakeman'] }
  let(:brakeman_report) { scan_report['info']['brakeman_report'][0] }
  let(:first_scan_warning) { brakeman_report['warnings'][0] }

  describe '#run' do
    context 'non-rails project' do
      it 'should record the STDERR of brakeman' do
        scanner = Salus::Scanners::Brakeman.new(
          repository: Salus::Repo.new('spec/fixtures/blank_repository'),
          report: report,
          config: blank_config
        )
        scanner.run
        expect(scan_report['stderr']).to include('Please supply the path to a Rails application')
      end
    end

    context 'rails project with vulnerabilities' do
      it 'should record failure and record the STDOUT from brakeman' do
        scanner = Salus::Scanners::Brakeman.new(
          repository: Salus::Repo.new('spec/fixtures/brakeman/vulnerable_rails_app'),
          report: report,
          config: blank_config
        )
        scanner.run

        expect(scan_report['passed']).to eq(false)

        expect(scan_report['stdout']).not_to eq(nil)
        expect(scan_report['stdout']).not_to eq("")

        expect(scan_report['info']['brakeman_report'].length).not_to equal(0)
        expect(scan_report['info']['brakeman_report'][0]).not_to equal(0)
        expect(scan_report['info']['brakeman_report'][0]['warnings'].length).not_to eq(0)
        expect(scan_report['info']['brakeman_report'][0]['warnings'][0]).not_to eq(0)

        expect(first_scan_warning['warning_type']).to eq('Dangerous Eval')
      end
    end
  end

  describe '#should_run?' do
    context 'no Gemfile nor Rails gem' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.gemfile_present?).to eq(false)
        scanner = Salus::Scanners::Brakeman.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'Gemfile present but no rails gem' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/ruby_app')
        expect(repo.gemfile_present?).to eq(true)
        expect(repo.gemfile).not_to match(/('|")rails('|")/)
        scanner = Salus::Scanners::Brakeman.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'Gemfile present with rails gem' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/safe_rails_app')
        expect(repo.gemfile_present?).to eq(true)
        expect(repo.gemfile).to match(/('|")rails('|")/)
        scanner = Salus::Scanners::Brakeman.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(true)
      end
    end
  end
end
