require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportRubyGems do
  let(:blank_config) { {} }
  let(:report) { Salus::Report.new }
  let(:scan_report) { json_report['scans']['ReportRubyGems'] }

  describe '#run' do
    context 'no Gemfile or Gemfile.lock present' do
      it 'should throw an error since there is nothing to parse' do
        scanner = Salus::Scanners::ReportRubyGems.new(
          repository: Salus::Repo.new('spec/fixtures/blank_repository'),
          report: report,
          config: blank_config
        )
        expect { scanner.run }.to raise_error(
          Salus::Scanners::Base::InvalidScannerInvocationError,
          'Cannot report on Ruby gems without a Gemfile or Gemfile.lock'
        )
      end
    end

    context 'Gemfile present only' do
      it 'should report on all the dependencies in the Gemfile' do
        scanner = Salus::Scanners::ReportRubyGems.new(
          repository: Salus::Repo.new('spec/fixtures/report_ruby_gems/gemfile_only'),
          report: report,
          config: blank_config
        )
        scanner.run
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile', 'type' => 'ruby', 'version' => '2.3.0'
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile',
          'type' => 'gem',
          'name' => 'kibana_url',
          'version' => '~> 1.0',
          'source' => 'https://rubygems.org/'
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile',
          'type' => 'gem',
          'name' => 'rails',
          'version' => '>= 0',
          'source' => 'https://rubygems.org/'
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile',
          'type' => 'gem',
          'name' => 'master_lock',
          'version' => '>= 0',
          'source' => 'git@github.com:coinbase/master_lock.git (at master)'
        )
      end
    end

    context 'Gemfile present without ruby version' do
      it 'should report on all the dependencies in the Gemfile' do
        scanner = Salus::Scanners::ReportRubyGems.new(
          repository: Salus::Repo.new(
            'spec/fixtures/report_ruby_gems/gemfile_without_ruby_version'
          ),
          report: report,
          config: blank_config
        )
        scanner.run
        expect(scan_report['info']['dependency']).not_to include(
          'dependency_file' => 'Gemfile', 'type' => 'ruby', 'version' => '2.3.0'
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile',
          'type' => 'gem',
          'name' => 'kibana_url',
          'version' => '~> 1.0',
          'source' => 'https://rubygems.org/'
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile',
          'type' => 'gem',
          'name' => 'rails',
          'version' => '>= 0',
          'source' => 'https://rubygems.org/'
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile',
          'type' => 'gem',
          'name' => 'master_lock',
          'version' => '>= 0',
          'source' => 'git@github.com:coinbase/master_lock.git (at master)'
        )
      end
    end

    context 'Gemfile and Gemfile.lock present' do
      it 'should report on all the dependencies in the Gemfile.lock file' do
        scanner = Salus::Scanners::ReportRubyGems.new(
          repository: Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile'),
          report: report,
          config: blank_config
        )
        scanner.run
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile', 'type' => 'ruby', 'version' => 'ruby 2.3.0p0'
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile', 'type' => 'bundler', 'version' => '1.15.1'
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile.lock',
          'type' => 'gem',
          'name' => 'actioncable',
          'version' => '5.1.2',
          'source' => match(%r{rubygems repository https:\/\/rubygems.org\/})
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile.lock',
          'type' => 'gem',
          'name' => 'kibana_url',
          'version' => '1.0.1',
          'source' => match(%r{rubygems repository https:\/\/rubygems.org\/})
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gemfile.lock',
          'type' => 'gem',
          'name' => 'master_lock',
          'version' => '0.9.1',
          'source' => 'git@github.com:coinbase/master_lock.git (at master@9dfd28d)'
        )
      end
    end
  end

  describe '#should_run?' do
    context 'no Gemfile or Gemfile.lock present' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.gemfile_present?).to eq(false)
        expect(repo.gemfile_lock_present?).to eq(false)
        scanner = Salus::Scanners::ReportRubyGems.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'Gemfile is present' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/gemfile_only')
        expect(repo.gemfile_present?).to eq(true)
        expect(repo.gemfile_lock_present?).to eq(false)
        scanner = Salus::Scanners::ReportRubyGems.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(true)
      end
    end

    context 'Gemfile.lock is present' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile')
        expect(repo.gemfile_lock_present?).to eq(true)
        scanner = Salus::Scanners::ReportRubyGems.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(true)
      end
    end
  end
end
