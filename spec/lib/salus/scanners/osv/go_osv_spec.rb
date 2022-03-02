require_relative '../../../../spec_helper.rb'
require 'json'

describe Salus::Scanners::OSV::GoOSV do
  describe '#run' do
    let(:osv) { "../../../../../spec/fixtures/osv/go_osv/" }
    let(:file) { File.expand_path(osv, __dir__) }

    def stub_req_with_empty_response
      stub_request(:get, "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip")
        .with(
          headers: {
            'Accept' => '*/*',
            'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
            'Host' => 'osv-vulnerabilities.storage.googleapis.com',
            'User-Agent' => 'Ruby'
          }
        )
        .to_return(
          status: 200,
          body: [],
          headers: {}
        )
    end

    def stub_req_with_400_response
      stub_request(:get, "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip")
        .with(
          headers: {
            'Accept' => '*/*',
            'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
            'Host' => 'osv-vulnerabilities.storage.googleapis.com',
            'User-Agent' => 'Ruby'
          }
        )
        .to_return(
          status: 400,
          body: File.read(File.join(file, 'all.zip')),
          headers: {}
        )
    end

    def stub_req_with_valid_response
      stub_request(:get, "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip")
        .with(
          headers: {
            'Accept' => '*/*',
            'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
            'Host' => 'osv-vulnerabilities.storage.googleapis.com',
            'User-Agent' => 'Ruby'
          }
        )
        .to_return(
          status: 200,
          body: File.read(File.join(file, 'all.zip')),
          headers: {}
        )
    end

    context 'with non-go project' do
      it 'should record an error to scanner report' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.package_lock_json_present?).to eq(false)
        scanner = Salus::Scanners::OSV::GoOSV.new(repository: repo, config: {})

        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'with vulnerable go project' do
      let(:path_str) { "../../../../../spec/fixtures/osv/go_osv" }
      let(:fixture_path) { File.expand_path(path_str, __dir__) }

      it 'should fail when vulnerable dependencies are found in go.sum' do
        repo = Salus::Repo.new(File.join(fixture_path, 'failure_vulnerability_present'))
        scanner = Salus::Scanners::OSV::GoOSV.new(repository: repo, config: {})
        stub_req_with_valid_response
        scanner.run

        expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      end

      it 'should pass when vulnerable dependencies found in go.sum have exceptions configured' do
        repo = Salus::Repo.new(File.join(fixture_path, 'failure_vulnerability_present'))
        config_data = YAML.load_file(File.join(fixture_path,
                                               'failure_vulnerability_present/salus.yaml'))
        scanner = Salus::Scanners::OSV::GoOSV.new(repository: repo,
            config: config_data["scanner_configs"]["GoOSV"])
        stub_req_with_valid_response
        scanner.run

        expect(scanner.report.to_h.fetch(:passed)).to eq(true)
      end

      it 'should fail when no dependencies are found in go.sum' do
        repo = Salus::Repo.new(File.join(fixture_path, 'no_dependency_found'))

        scanner = Salus::Scanners::OSV::GoOSV.new(repository: repo, config: {})
        stub_req_with_valid_response
        scanner.run
        expect(scanner.report.to_h.fetch(:passed)).to eq(false)

        msg = "GoOSV: Failed to parse any dependencies from the project."
        expect(scanner.report.to_h.fetch(:errors).first.fetch(:message)).to include(msg)
      end

      it 'should fail when OSV returns error' do
        repo = Salus::Repo.new(File.join(fixture_path, 'failure_vulnerability_present'))
        scanner = Salus::Scanners::OSV::GoOSV.new(repository: repo, config: {})
        stub_req_with_400_response
        scanner.run

        expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      end

      it 'should fail when OSV returns empty data' do
        stub_req_with_empty_response
        repo = Salus::Repo.new(File.join(fixture_path, 'failure_vulnerability_present'))
        scanner = Salus::Scanners::OSV::GoOSV.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.to_h.fetch(:passed)).to eq(false)
      end
    end

    context 'with non vulnerable go project' do
      let(:path_str) { "../../../../../spec/fixtures/osv/go_osv" }
      let(:fixture_path) { File.expand_path(path_str, __dir__) }

      it 'should pass when no vulnerabilities are found in go.sum' do
        repo = Salus::Repo.new(File.join(fixture_path, 'success_no_vulnerability'))
        scanner = Salus::Scanners::OSV::GoOSV.new(repository: repo, config: {})
        stub_req_with_valid_response
        scanner.run

        expect(scanner.report.to_h.fetch(:passed)).to eq(true)
      end
    end
  end
end
