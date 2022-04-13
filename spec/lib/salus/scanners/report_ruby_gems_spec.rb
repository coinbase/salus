require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportRubyGems do
  describe '#run' do
    before do
      allow_any_instance_of(described_class).to receive(:find_licenses_for).and_return(['MIT'])
    end

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
            source: 'https://rubygems.org/',
            licenses: ['MIT']
          },
          {
            dependency_file: 'Gemfile',
            type: 'gem',
            name: 'rails',
            version: '>= 0',
            source: 'https://rubygems.org/',
            licenses: ['MIT']
          },
          {
            dependency_file: 'Gemfile',
            type: 'gem',
            name: 'master_lock',
            version: '>= 0',
            source: 'git@github.com:coinbase/master_lock.git',
            licenses: ['MIT']
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
          source: "locally installed gems",
          licenses: ['MIT']
        },
        {
          dependency_file: 'Gemfile.lock',
          type: 'gem',
          name: 'kibana_url',
          version: '1.0.1',
          source: "locally installed gems",
          licenses: ['MIT']
        },
        {
          dependency_file: 'Gemfile.lock',
          type: 'gem',
          name: 'master_lock',
          version: '0.9.1',
          source: 'git@github.com:coinbase/master_lock.git',
          licenses: ['MIT']
        }
      ]

      expect(info[:dependencies]).to include(*expected)
    end
  end

  describe '#find_licenses_for' do
    let(:repo) { Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile') }
    let(:scanner) { Salus::Scanners::ReportRubyGems.new(repository: repo, config: {}) }
    let(:gem_name) { 'bundler-audit' }
    let(:gem_version) { '0.8.0' }
    let(:gem_license) { 'MIT' }

    let(:ok_code) { 200 }
    let(:not_found_code) { 404 }
    let(:internal_server_error_code) { 500 }
    let(:too_many_req_error_code) { 429 }

    let(:request_str) do
      "https://rubygems.org/api/v2/rubygems/#{gem_name}/versions/#{gem_version}.json"
    end

    let(:response_body) do
      "{\"name\":\"#{gem_name}\",\"version\":\"#{gem_version}\",\"licenses\":[\"MIT\"]}"
    end

    let(:response_body_with_no_license) do
      "{\"name\":\"#{gem_name}\",\"version\":\"#{gem_version}\",\"licenses\":[]}"
    end

    def stub_req_with(request_str, response_body, response_status)
      stub_request(:get, request_str)
        .with(
          headers: {
            'Accept' => '*/*',
            'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
            'Host' => 'rubygems.org',
            'User-Agent' => 'Ruby'
          }
        )
        .to_return(status: response_status, body: response_body, headers: {})
    end

    context 'with successful request' do
      it 'should return a list of valid licenses' do
        stub_req_with(request_str, response_body, ok_code)
        expect(scanner.send(:find_licenses_for, gem_name,
                            gem_version)).to include(gem_license)
      end

      it 'should return an empty array if there exists no license' do
        stub_req_with(request_str, response_body_with_no_license, ok_code)
        expect(scanner.send(:find_licenses_for, gem_name,
                            gem_version)).to be_empty
      end
    end

    it 'should return an empty array if there occurs too many requests' do
      msg = "Too many requests for rubygems api after " \
        "#{described_class::MAX_RETRIES_FOR_RUBY_GEMS_API} retries"
      stub_req_with(request_str, '', too_many_req_error_code)

      expect_any_instance_of(described_class).to receive(:bugsnag_notify).with(msg)
      expect(scanner.send(:find_licenses_for, gem_name,
                          gem_version)).to be_empty
    end

    it 'should return an empty array if the gem does not exist' do
      stub_req_with(request_str, '', not_found_code)
      expect(scanner.send(:find_licenses_for, gem_name,
                          gem_version)).to be_empty
    end

    it 'should return an empty array if there is an error in the api call to rubygems.org' do
      msg = "Unable to gather license information using rubygems api with error " \
        "message Salus::Scanners::ReportRubyGems::RubyGemsApiError: Server error"
      stub_req_with(request_str, 'Server error', internal_server_error_code)

      expect_any_instance_of(described_class).to receive(:bugsnag_notify).with(msg)
      expect(scanner.send(:find_licenses_for, gem_name,
                          gem_version)).to be_empty
    end

    it 'should return an empty array if there is an error' do
      allow(JSON).to receive(:parse).and_raise(StandardError.new("Error in parsing"))
      stub_req_with(request_str, response_body_with_no_license, ok_code)
      expect(scanner.send(:find_licenses_for, gem_name,
                          gem_version)).to be_empty
    end

    it 'should return an empty array if there exists no license for the gem' do
      allow(JSON).to receive(:parse).and_return([])
      stub_req_with(request_str, response_body_with_no_license, ok_code)
      expect(scanner.send(:find_licenses_for, gem_name,
                          gem_version)).to be_empty
    end
  end

  describe '#spdx_license_for' do
    let(:repo) { Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile') }
    let(:scanner) { Salus::Scanners::ReportRubyGems.new(repository: repo, config: {}) }

    it 'should return a valid spdx formatted license for a given license' do
      expect(scanner.send(:spdx_license_for, 'MIT')).to eql('MIT')
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

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
        expect(scanner.version).to eq('')
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::ReportRubyGems.supported_languages
        expect(langs).to eq(['ruby'])
      end
    end
  end
end
