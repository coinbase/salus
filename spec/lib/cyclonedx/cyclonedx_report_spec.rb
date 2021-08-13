require_relative '../../spec_helper'
require 'json'
require 'json-schema'

describe Cyclonedx::ReportRubyGems do
  let(:scan_reports) { [] }

  describe "to_cyclonedx schema validation" do
    let(:repo) { Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile') }
    let(:name) { 'Cool Report' }
    let(:report) { Salus::Report.new(project_name: name) }

    it 'succeeds if generated cyclonedx format is correct' do
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run
      report.add_scan_report(scanner.report, required: false)
      expect { report.to_cyclonedx }.not_to raise_error
    end

    it 'succeeds if generated cyclonedx version is empty' do
      path = File.expand_path('../..//fixtures/cyclonedx/no_version.json', __dir__)
      report = JSON.parse(File.read(path))
      expect(Cyclonedx::Report.validate_cyclonedx(report)).to eq(report)
    end

    it 'fails if generated cyclonedx report is not valid' do
      path = File.expand_path('../..//fixtures/cyclonedx/invalid_report.json', __dir__)
      report = JSON.parse(File.read(path))
      error = Cyclonedx::Report::CycloneDXInvalidFormatError
      expect { Cyclonedx::Report.validate_cyclonedx(report) }.to raise_error(error)
    end
  end
end
