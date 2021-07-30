require_relative '../../spec_helper'
require 'json'
require 'json-schema'

describe Cyclonedx::ReportRubyGems do
  let(:scan_reports) { [] }

  describe "to_cyclonedx" do
    let(:repo) { Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile') }
    let(:name) { 'Cool Report' }
    let(:custom_info) { { bitcoin_price: 100_000 } }
    let(:config) { { lemurs: 'contained', raptors: 'loose' } }
    let(:build) { { "url": "https://github.com" } }
    let(:report) { Salus::Report.new(project_name: name, custom_info: custom_info, builds: build) }

    it 'succeeds if generated cyclonedx format is correct' do
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run
      report.add_scan_report(scanner.report, required: false)
      expect(report.to_cyclonedx).to include('"bomFormat": "CycloneDX"')
    end

    it 'succeeds if generated cyclonedx version is empty' do
      path = File.expand_path('../..//fixtures/cyclonedx/no_version.json', __dir__)
      report = JSON.parse(File.read(path))
      expect(Cyclonedx::Report.validate_cyclonedx(report)).to eq(report)
    end

    it 'succeeds if generated cyclonedx version is empty' do
      path = File.expand_path('../..//fixtures/cyclonedx/no_version.json', __dir__)
      report = JSON.parse(File.read(path))
      expect(Cyclonedx::Report.validate_cyclonedx(report)).to eq(report)
    end
  end
end
