require_relative '../../spec_helper.rb'

RSpec::Matchers.define :match_report_json do |expected|
  def remove_key(json_string, key = 'running_time')
    json = JSON.parse(json_string)
    json.delete(key)
    json['scans'].each do |scanner, _|
      json['scans'][scanner].delete(key)
    end

    return json if json.dig('config', 'report_uris').nil?

    # Avoid comparing relative and absolute file:///
    json['config']['report_uris'].each_with_index do |endpoint, index|
      json['config']['report_uris'][index].delete('uri') if endpoint['uri'] =~ /^file:/
    end
    json
  end

  match do |actual|
    remove_key(actual) == remove_key(expected)
  end
end

RSpec::Matchers.define :match_cyclonedx_report_json do |expected|
  def remove_key(json_string, encoded = false)
    json = JSON.parse(json_string)
    json['bom'] = JSON.parse(Base64.decode64(json['bom'])) if encoded
    json['bom'].delete('serialNumber')
    json
  end

  match do |actual|
    remove_key(actual, true) == remove_key(expected)
  end
end

describe Salus::Processor do
  before do
    allow_any_instance_of(Salus::Scanners::ReportRubyGems)
      .to receive(:find_licenses_for)
      .and_return(['MIT'])
  end

  describe '#initialize' do
    let(:config_file_path) { 'spec/fixtures/processor/repo/salus.yaml' }
    let(:config_file)      { File.read(config_file_path) }
    let(:file_config_file) do
      File.read('spec/fixtures/processor/explicit_config/repo/explicit_salus.yaml')
    end
    let(:file_config_uri)  { "file:///explicit_salus.yaml" }
    let(:http_config_uri)  { 'https://nerv.com/salus/config' }
    let(:http_config_file) { config_file }
    let(:missing_config_uri) { "file:///namewithtypo.yaml" }

    context 'explicit sources of config given files given' do
      it 'should load the config from the given file and URI sources and add them to the report' do
        stub_request(:get, http_config_uri).to_return(status: 200, body: config_file)
        expect(Salus::Config).to receive(:new)
          .once
          .with([file_config_file, http_config_file], [])
          .and_call_original

        Dir.chdir('spec/fixtures/processor/explicit_config') do
          processor = Salus::Processor.new([file_config_uri, http_config_uri])
          reported_config = processor.report.to_h[:config]
          expect(reported_config[:sources][:valid]).to include(file_config_uri, http_config_uri)
          expect(reported_config[:active_scanners]).to include(
            'BundleAudit',
            'Brakeman',
            'Gosec',
            'PatternSearch',
            'ReportGoDep',
            'ReportNodeModules',
            'ReportRubyGems'
          )
          expect(reported_config[:enforced_scanners]).to include('BundleAudit', 'Brakeman')
        end
      end

      it 'should expand the repo path provided' do
        processor = Salus::Processor.new
        path = processor.instance_variable_get(:@repo_path)
        # The default repo path is relative ./repo, we are expecting
        # the path to be expanded
        expect(path).not_to eq(Salus::DEFAULT_REPO_PATH)
      end

      it 'fetch_config_file should return nil if file content is not hash' do
        stub_request(:get, http_config_uri).to_return(status: 200, body: "{'A': 'B'}")
        result = Salus::Processor.new.fetch_config_file(http_config_uri, '/home/repo')
        expect(result).to eq("{'A': 'B'}")

        stub_request(:get, http_config_uri).to_return(status: 200, body: "false")
        result = Salus::Processor.new.fetch_config_file(http_config_uri, '/home/repo')
        expect(result).to be_nil
      end

      it 'should not use config files when they do not exist' do
        expect(Salus::Config).to receive(:new).once.and_call_original
        Dir.chdir('spec/fixtures/processor/repo') do
          processor = Salus::Processor.new([missing_config_uri])

          reported_config = processor.report.to_h[:config]
          expect(reported_config[:sources][:configured]).to eq([missing_config_uri])
          expect(reported_config[:sources][:valid]).to eq([])
          expect(reported_config[:active_scanners]).to include(
            'BundleAudit',
            'Brakeman',
            'PatternSearch',
            'ReportGoDep',
            'ReportNodeModules',
            'ReportRubyGems'
          )
          expect(reported_config[:enforced_scanners]).not_to be_empty
        end
      end
    end

    context 'implicitly look for file' do
      it 'should load the default config from the salus.yaml and add to report' do
        expect(Salus::Config).to receive(:new).once.with([config_file], []).and_call_original
        Dir.chdir('spec/fixtures/processor') do
          processor = Salus::Processor.new

          reported_config = processor.report.to_h[:config]
          expect(reported_config[:sources][:valid]).to eq(['file:///salus.yaml'])
          expect(reported_config[:active_scanners]).to include(
            'BundleAudit',
            'Brakeman',
            'PatternSearch',
            'ReportGoDep',
            'ReportNodeModules',
            'ReportRubyGems'
          )
          expect(reported_config[:enforced_scanners]).to include('BundleAudit', 'Brakeman')
        end
      end
    end
  end

  describe '#scan_project' do
    it 'should scan the project given by a particular path' do
      processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/explicit_path')
      processor.scan_project
      expect(processor.passed?).to eq(false)

      report_hsh = processor.report.to_h

      expect(report_hsh[:project_name]).to eq('EVA-01')
      expect(report_hsh[:custom_info]).to eq('Purple unit')
      expect(report_hsh[:version]).to eq(Salus::VERSION)
      expect(report_hsh[:passed]).to eq(false)
      expect(report_hsh[:errors]).to eq([])

      expect(report_hsh[:scans]['BundleAudit'][:passed]).to eq(false)
      expect(report_hsh[:scans]['BundleAudit'][:info][:vulnerabilities].length).to be_positive

      cves = report_hsh[:scans]['BundleAudit'][:info][:vulnerabilities].map { |vuln| vuln[:cve] }
      expect(cves).to include('CVE-2016-6316')
    end

    it 'should override the configured active scanners when they\'re provided via command line' do
      processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/allowlist_scanners',
        cli_scanners_to_run: %w[Brakeman CargoAudit NPMAudit])
      processor.scan_project

      report_hsh = processor.report.to_h

      expect(report_hsh[:config][:active_scanners].length).to eq(3)
      expect(report_hsh[:config][:active_scanners][0]).to eq('Brakeman')
      expect(report_hsh[:config][:active_scanners][1]).to eq('CargoAudit')
      expect(report_hsh[:config][:active_scanners][2]).to eq('NPMAudit')
    end

    it 'should scan the project using only scanners provided from the command line' do
      processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/allowlist_scanners',
        cli_scanners_to_run: %w[Brakeman NPMAudit])
      processor.scan_project

      expect(processor.passed?).to eq(false)

      report_hsh = processor.report.to_h

      expect(report_hsh[:config][:active_scanners].length).to eq(2)
      expect(report_hsh[:config][:active_scanners][0]).to eq('Brakeman')
      expect(report_hsh[:config][:active_scanners][1]).to eq('NPMAudit')

      expect(report_hsh[:project_name]).to eq('EVA-01')
      expect(report_hsh[:custom_info]).to eq('Purple unit')
      expect(report_hsh[:version]).to eq(Salus::VERSION)
      expect(report_hsh[:passed]).to eq(false)
      expect(report_hsh[:errors]).to eq([])

      expect(report_hsh[:scans]['Brakeman'][:passed]).to eq(false)
      expect(report_hsh[:scans]['Brakeman'][:info][:stdout].length).to be_positive
      expect(report_hsh[:scans]['Brakeman'][:logs].length).to be_positive

      expect(report_hsh[:scans]['NPMAudit'][:passed]).to eq(false)
      expect(report_hsh[:scans]['NPMAudit'][:info][:stdout][:actions].length).to be_positive
      expect(report_hsh[:scans]['NPMAudit'][:logs].length).to be_positive
    end

    it 'should recurse when configured' do
      path = 'spec/fixtures/processor/recursive'

      processor = Salus::Processor.new(repo_path: path,
        cli_scanners_to_run: %w[Brakeman NPMAudit])

      processor.scan_project

      processor.report.report_uris.reject! { |u| u['format'] == FULL_SARIF_DIFF_FORMAT }

      sarif = processor.report.to_sarif
      json = JSON.parse(sarif)

      # We should have multiple runs of Brakeman
      scanners = json['runs'].map { |run| run.dig('tool', 'driver', 'name') }.sort
      expect(scanners).to eq(%w[Brakeman Brakeman NPMAudit])

      # We should not have vendors here (excluded)
      scanned_dirs = json['runs'].map do |run|
        run.dig('originalUriBaseIds', 'SRCROOT', 'uri')
      end.uniq.sort

      expect(scanned_dirs).to eq(['.', 'project-two'])
    end
  end

  describe '#passed?' do
    it 'should return false if the overall scan did not pass' do
      processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/explicit_path_failure')
      processor.scan_project
      expect(processor.passed?).to eq(false)
    end

    it 'should return true if the overall scan passed' do
      processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/explicit_path_success')
      processor.scan_project
      expect(processor.passed?).to eq(true)
    end
  end

  describe '#export_report' do
    context 'remote URI' do
      let(:expected_report) do
        File.read('spec/fixtures/processor/remote_uri/expected_report.json').strip
      end
      let(:remote_uri) { 'https://nerv.tk3/salus-report' }

      it 'should send the report to the remote URI' do
        stub_request(:post, remote_uri)
          .with(headers: { 'Content-Type' => 'application/json' })
          .to_return(status: 202)

        processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/remote_uri')
        processor.scan_project
        processor.export_report

        assert_requested(
          :post,
          remote_uri,
          headers: { 'Content-Type' => 'application/json' },
          times: 1
        ) do |req|
          expect(req.body).to match_report_json(expected_report)
        end
      end

      it 'Expect 0 report_uris for report_filter set to none' do
        stub_request(:post, remote_uri)
          .with(headers: { 'Content-Type' => 'application/json' })
          .to_return(status: 202)
        processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/remote_uri',
                                         report_filter: 'none')
        expect(processor.report.report_uris.size).to eq(0)
      end
    end

    context 'local URI' do
      let(:expected_report) do
        File.read('spec/fixtures/processor/local_uri/expected_report.json').strip
      end
      let(:repo_relative_uri) { 'salus_reports_folder/salus-report.json' } # set in salus.yaml
      let(:local_uri) { "spec/fixtures/processor/local_uri/#{repo_relative_uri}" }
      let(:report_file_path) { "#{local_uri}/salus_report.json" }

      it 'should write the report to the local file system based on a path in the given repo' do
        # cleanup from preivous test if last cleanup failed
        remove_file(local_uri)

        processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/local_uri')
        processor.scan_project
        processor.export_report

        expect(File.read(local_uri)).to match_report_json(expected_report, true)

        # remove report file that was generated from Salus execution
        remove_file(local_uri)
      end
    end

    context 'multiple URIs' do
      let(:expected_report) do
        File.read('spec/fixtures/processor/remote_uri/expected_report.json').strip
      end
      let(:remote_uri_one) { 'https://nerv.tk3/foo-salus-report' }
      let(:remote_uri_two) { 'https://nerv.tk3/salus-report' }

      it 'should still send the 2nd report to the remote URI' do
        stub_request(:post, remote_uri_one)
          .with(headers: { 'Content-Type' => 'application/json' })
          .and_raise(StandardError.new("error"))

        stub_request(:post, remote_uri_two)
          .with(headers: { 'Content-Type' => 'application/json' })
          .to_return(status: 202)

        Salus::ReportRequest.should_receive(:send_report).twice

        processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/multiple_endpoints')
        processor.scan_project
        processor.export_report
      end
    end

    context 'remote URI headers verbs' do
      prefix = 'spec/fixtures/processor/remote_uri_headers_verbs'
      let(:expected_report) do
        File.read("#{prefix}/expected_report.json").strip
      end
      let(:expected_report_no_project_name) do
        File.read("#{prefix}/expected_report_no_project_name.json").strip
      end
      let(:expected_report_no_cyclonedx_options) do
        File.read("#{prefix}/expected_report_no_cyclonedx_options.json").strip
      end

      let(:remote_uri) { 'https://nerv.tk3/salus-report' }
      let(:remote_uri1) { 'https://nerv.tk4/salus-report' }
      let(:remote_uri2) { 'https://nerv.tk5/salus-report' }

      it 'should send the report to the remote URI with correct headers and verb' do
        allow(ENV).to receive(:[]).and_call_original # allow calls in general
        allow(ENV).to receive(:[]).with('RUNNING_SALUS_TESTS').and_return(nil) # otherwise aborts
        allow(ENV).to receive(:[]).with('DUMMY_API_KEY').and_return('123456789')
        allow(ENV).to receive(:[]).with('SALUS_BUILD_ORG').and_return('random_org')
        allow(ENV).to receive(:[]).with('SALUS_BUILD_PROJECT').and_return('random_project')

        stub_request(:put, remote_uri)
          .with(headers: { 'Content-Type' => 'application/json',
                           'X-API-Key' => '123456789',
                           'repo' => 'Random Repo' },
                body: {})
          .to_return(status: 202)

        stub_request(:post, remote_uri1)
          .with(headers: { 'Content-Type' => 'application/json',
                           'X-API-Key' => '123456789',
                           'repo' => 'Random Repo' },
                body: {})
          .to_return(status: 202)

        stub_request(:put, remote_uri2)
          .with(headers: { 'Content-Type' => 'application/json',
                           'X-API-Key' => '123456789',
                           'repo' => 'Random Repo' },
                body: {})
          .to_return(status: 202)

        processor = Salus::Processor.new(
          repo_path: 'spec/fixtures/processor/remote_uri_headers_verbs'
        )
        processor.scan_project
        processor.export_report

        assert_requested(
          :put,
          remote_uri,
          headers:
            {
              'Content-Type' => 'application/json',
              'X-API-Key' => '123456789',
              'repo' => 'Random Repo'
            },
          times: 1
        ) do |req|
          expect(req.body).to match_cyclonedx_report_json(expected_report)
        end

        assert_requested(
          :post,
          remote_uri1,
          headers:
            {
              'Content-Type' => 'application/json',
              'X-API-Key' => '123456789',
              'repo' => 'Random Repo'
            },
          times: 1
        ) do |req|
          expect(req.body).to match_cyclonedx_report_json(expected_report_no_project_name)
        end

        assert_requested(
          :put,
          remote_uri2,
          headers:
            {
              'Content-Type' => 'application/json',
              'X-API-Key' => '123456789',
              'repo' => 'Random Repo'
            },
          times: 1
        ) do |req|
          expect(req.body).to match_cyclonedx_report_json(expected_report_no_cyclonedx_options)
        end
      end
    end
  end
end
