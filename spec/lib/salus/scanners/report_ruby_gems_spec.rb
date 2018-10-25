require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportRubyGems do
  describe '#run' do
    it 'should throw an error in the absence of Gemfile/Gemfile.lock' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})

      expect { scanner.run }.to raise_error(
        Salus::Scanners::Base::InvalidScannerInvocationError,
        'Cannot report on Ruby gems without a Gemfile or Gemfile.lock'
      )
    end

    it 'should report all the deps in the Gemfile if Gemfile.lock is absent' do
      repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/gemfile_only')
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run

      info = scanner.report.to_h.fetch(:info)

      expect(info[:ruby_version]).to eq('2.3.0')

      expect(info[:dependencies]).to match_array(
        [
          {
            dependency_file: 'Gemfile',
            type: 'gem',
            name: 'kibana_url',
            version: '~> 1.0',
            source: 'https://rubygems.org/'
          },
          {
            dependency_file: 'Gemfile',
            type: 'gem',
            name: 'rails',
            version: '>= 0',
            source: 'https://rubygems.org/'
          },
          {
            dependency_file: 'Gemfile',
            type: 'gem',
            name: 'master_lock',
            version: '>= 0',
            source: 'git@github.com:coinbase/master_lock.git (at master)'
          }
        ]
      )
    end

    it 'should report all deps in Gemfile.lock' do
      repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile')
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run

      info = scanner.report.to_h.fetch(:info)

      expect(info[:ruby_version]).to eq('ruby 2.3.0p0')
      expect(info[:bundler_version]).to eq('1.15.1')

      expected = [
        {
          dependency_file: 'Gemfile.lock',
          type: 'gem',
          name: 'actioncable',
          version: '5.1.2',
          source: match(%r{rubygems repository https:\/\/rubygems.org\/})
        },
        {
          dependency_file: 'Gemfile.lock',
          type: 'gem',
          name: 'kibana_url',
          version: '1.0.1',
          source: match(%r{rubygems repository https:\/\/rubygems.org\/})
        },
        dependency_file: 'Gemfile.lock',
        type: 'gem',
        name: 'master_lock',
        version: '0.9.1',
        source: 'git@github.com:coinbase/master_lock.git (at master@9dfd28d)'
      ]

      expect(info[:dependencies]).to include(*expected)
    end
  end

  describe '#should_run?' do
    context 'no Gemfile or Gemfile.lock present' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.gemfile_present?).to eq(false)
        expect(repo.gemfile_lock_present?).to eq(false)
        scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'Gemfile is present' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/gemfile_only')
        expect(repo.gemfile_present?).to eq(true)
        expect(repo.gemfile_lock_present?).to eq(false)
        scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(true)
      end
    end

    context 'Gemfile.lock is present' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile')
        expect(repo.gemfile_lock_present?).to eq(true)
        scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(true)
      end
    end
  end
end
