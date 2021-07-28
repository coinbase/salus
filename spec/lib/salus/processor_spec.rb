require_relative '../../spec_helper.rb'

RSpec::Matchers.define :match_report_json do |expected|
  def remove_key(json_string, key = 'running_time')
    json = JSON.parse(json_string)
    json.delete(key)
    json['scans'].each do |scanner, _|
      json['scans'][scanner].delete(key)
    end
    json
  end

  match do |actual|
    remove_key(actual) == remove_key(expected)
  end
end

describe Salus::Processor do
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

    it 'should not run excluded scanners' do
      processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/exclude_scanner')
      processor.scan_project

      

      report_hsh = processor.report.to_h
      expect(report_hsh[:scans].include?('BundleAudit')).to eq(false)

      expect(report_hsh[:project_name]).to eq('EVA-01')
      expect(report_hsh[:custom_info]).to eq('Purple unit')
      expect(report_hsh[:version]).to eq(Salus::VERSION)
      expect(report_hsh[:errors]).to eq([])
      expect(report_hsh[:passed]).to eq(true)
      expect(processor.passed?).to eq(true)

      
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

        expect(File.read(local_uri)).to match_report_json(expected_report)

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

        expect_any_instance_of(Salus::Report).to receive(:send_report).twice

        processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/multiple_endpoints')
        processor.scan_project
        processor.export_report
      end
    end
  end
end
