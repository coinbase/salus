require_relative '../../spec_helper'
require 'json'
require 'json-schema'

describe Cyclonedx::ReportRubyGems do
  before do
    allow_any_instance_of(Salus::Scanners::ReportRubyGems)
      .to receive(:find_licenses_for)
      .and_return(['MIT'])
  end

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

    it 'succeeds if generated cyclonedx format is correct' do
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})
      scanner.run
      report.add_scan_report(scanner.report, required: false)
      expect { report.to_cyclonedx }.not_to raise_error
    end

    it 'succeeds if generated cyclonedx version is empty' do
      path = File.expand_path('../..//fixtures/cyclonedx/no_version.json', __dir__)
      report = JSON.parse(File.read(path)).with_indifferent_access

      expect(Cyclonedx::Report.validate_cyclonedx(report)).to eq(report)
    end

    it 'succeeds if scan_reports contain duplicate reports' do
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run

      # scanner.report has been provided 2 times to Cyclonedx::Report.new to simulate duplication
      cyclonedx_reports = Cyclonedx::Report.new([[scanner.report, false], [scanner.report, false]],
                                                { "spec_version" => "1.3" })
      expect { cyclonedx_reports.to_cyclonedx }.not_to raise_error
    end

    it 'fails if generated cyclonedx report is not valid' do
      path = File.expand_path('../..//fixtures/cyclonedx/invalid_report.json', __dir__)
      report = JSON.parse(File.read(path)).with_indifferent_access
      error = Cyclonedx::Report::CycloneDXInvalidFormatError
      expect { Cyclonedx::Report.validate_cyclonedx(report) }.to raise_error(error)
    end
  end

  describe "to_cyclonedx spec version validation" do
    let(:repo) { Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile') }
    let(:name) { 'Cool Report' }
    let(:report) { Salus::Report.new(project_name: name) }

    it 'cylonedx spec version 1.2 does not include properties field' do
      repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile')
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run

      ruby_cyclonedx = Cyclonedx::ReportRubyGems.new(scanner.report, { "spec_version" => "1.2" })
      expected = [
        {
          "type": "library",
          "group": "",
          "name": "actioncable",
          "version": "5.1.2",
          "purl": "pkg:gem/actioncable@5.1.2",
          "licenses": [{ "license" => { "id" => "MIT" } }]
        },
        {
          "type": "library",
          "group": "",
          "name": "actionmailer",
          "version": "5.1.2",
          "purl": "pkg:gem/actionmailer@5.1.2",
          "licenses": [{ "license" => { "id" => "MIT" } }]
        },
        {
          "type": "library",
          "group": "",
          "name": "actionpack",
          "version": "5.1.2",
          "purl": "pkg:gem/actionpack@5.1.2",
          "licenses": [{ "license" => { "id" => "MIT" } }]
        }
      ]
      expect(ruby_cyclonedx.build_components_object).to include(*expected)
    end

    it 'cylonedx spec version 1.3 does include properties field' do
      repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile')
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run

      ruby_cyclonedx = Cyclonedx::ReportRubyGems.new(scanner.report, { "spec_version" => "1.3" })
      expected = [
        {
          "type": "library",
          "group": "",
          "licenses": [{ "license" => { "id" => "MIT" } }],
          "name": "actioncable",
          "version": "5.1.2",
          "purl": "pkg:gem/actioncable@5.1.2"
        },
        {
          "type": "library",
          "group": "",
          "licenses": [{ "license" => { "id" => "MIT" } }],
          "name": "actionmailer",
          "version": "5.1.2",
          "purl": "pkg:gem/actionmailer@5.1.2"
        },
        {
          "type": "library",
          "group": "",
          "licenses": [{ "license" => { "id" => "MIT" } }],
          "name": "actionpack",
          "version": "5.1.2",
          "purl": "pkg:gem/actionpack@5.1.2"
        }
      ]
      expect(ruby_cyclonedx.build_components_object).to include(*expected)
    end

    it 'fails if provided cylonedx spec version is unsupported' do
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run

      error = Cyclonedx::Report::CycloneDXInvalidVersionError
      cyclonedx_reports = Cyclonedx::Report.new([[scanner.report, false]],
                                                { "spec_version" => "1.0" })
      expect { cyclonedx_reports.to_cyclonedx }.to raise_error(error)
    end
  end
end
