require_relative '../../spec_helper.rb'

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

    context 'explicit sources of config given files given' do
      it 'should load the config from the given file and URI sources and add them to the report' do
        stub_request(:get, http_config_uri).to_return(status: 200, body: config_file)
        expect(Salus::Config).to receive(:new)
          .once
          .with([file_config_file, http_config_file])
          .and_call_original

        Dir.chdir('spec/fixtures/processor/explicit_config') do
          processor = Salus::Processor.new([file_config_uri, http_config_uri])

          reported_config = processor.report.to_h[:config]
          expect(reported_config[:sources]).to include(file_config_uri, http_config_uri)
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

    context 'implicitly look for file' do
      it 'should load the default config from the salus.yaml and add to report' do
        expect(Salus::Config).to receive(:new).once.with([config_file]).and_call_original
        Dir.chdir('spec/fixtures/processor') do
          processor = Salus::Processor.new

          reported_config = processor.report.to_h[:config]
          expect(reported_config[:sources]).to eq(['file:///salus.yaml'])
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

    context 'no config given' do
      it 'should use default configuration and report it' do
        expect(Salus::Config).to receive(:new).once.with([]).and_call_original
        Dir.chdir('spec/fixtures/blank_repository') do
          processor = Salus::Processor.new

          reported_config = processor.report.to_h[:config]
          expect(reported_config[:sources]).to eq(['file:///salus.yaml'])
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
  end

  describe '#scan_project' do
    it 'should scan the project given by a particular path' do
      processor = Salus::Processor.new(repo_path: 'spec/fixtures/processor/explicit_path')
      processor.scan_project

      expect(processor.passed?).to eq(false)

      report_hsh = processor.report.to_h

      expect(report_hsh[:project_name]).to eq('EVA-01')
      expect(report_hsh[:custom_info]).to eq('Purple unit')
      expect(report_hsh[:version]).to eq('1.0.0')
      expect(report_hsh[:passed]).to eq(false)
      expect(report_hsh[:errors]).to eq([])

      expect(report_hsh[:scans]['BundleAudit'][:passed]).to eq(false)
      expect(report_hsh[:scans]['BundleAudit'][:info][:vulnerabilities].length).to be_positive
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
          body: expected_report,
          times: 1
        )
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

        expect(File.read(local_uri)).to eq(expected_report)

        # remove report file that was generated from Salus execution
        remove_file(local_uri)
      end
    end
  end
end
