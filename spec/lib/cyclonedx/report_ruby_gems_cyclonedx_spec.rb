require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportRubyGems do
  before do
    allow_any_instance_of(Salus::Scanners::ReportRubyGems)
      .to receive(:find_licenses_for)
      .and_return(['MIT'])
  end

  describe "#run" do
    it 'should report all the deps in the Gemfile if Gemfile.lock is absent in cyclonedx' do
      repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/gemfile_only')
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run

      ruby_cyclonedx = Cyclonedx::ReportRubyGems.new(scanner.report)
      expect(ruby_cyclonedx.build_components_object).to match_array(
        [
          {
            "type": "library",
          "group": "",
            "licenses": [{ "license" => { "id" => "MIT" } }],
            "name": "kibana_url",
            "version": "~> 1.0",
            "purl": "pkg:gem/kibana_url"
          },
          {
            "type": "library",
          "group": "",
            "licenses": [{ "license" => { "id" => "MIT" } }],
            "name": "rails",
            "version": ">= 0",
            "purl": "pkg:gem/rails"
          },
          {
            "type": "library",
          "group": "",
            "licenses": [{ "license" => { "id" => "MIT" } }],
            "name": "master_lock",
            "version": ">= 0",
            "purl": "pkg:gem/master_lock"
          }
        ]
      )
    end

    it 'should report all deps in Gemfile.lock in cyclonedx' do
      repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile')
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run

      ruby_cyclonedx = Cyclonedx::ReportRubyGems.new(scanner.report)
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
        },
        {
          "type": "library",
          "group": "",
          "licenses": [{ "license" => { "id" => "MIT" } }],
          "name": "nio4r",
          "version": "2.1.0",
          "purl": "pkg:gem/nio4r@2.1.0"
        },
        {
          "type": "library",
          "group": "",
          "licenses": [{ "license" => { "id" => "MIT" } }],
          "name": "kibana_url",
          "version": "1.0.1",
          "purl": "pkg:gem/kibana_url@1.0.1"
        },
        {
          "type": "library",
          "group": "",
          "licenses": [{ "license" => { "id" => "MIT" } }],
          "name": "master_lock",
          "version": "0.9.1",
          "purl": "pkg:gem/master_lock@0.9.1"
        }
      ]
      expect(ruby_cyclonedx.build_components_object).to include(*expected)
    end

    it 'should report all deps from multiple sources in Gemfile.lock in cyclonedx' do
      repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/lockfile_multiple_sources')
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run

      ruby_cyclonedx = Cyclonedx::ReportRubyGems.new(scanner.report)
      expected = [
        {
          "type": "library",
          "group": "",
          "licenses": [{ "license" => { "id" => "MIT" } }],
          "name": "dep1",
          "version": "0.0.47",
          "purl": "pkg:gem/dep1@0.0.47"
        },
        {
          "type": "library",
          "group": "",
          "licenses": [{ "license" => { "id" => "MIT" } }],
          "name": "dep2",
          "version": "0.15.3",
          "purl": "pkg:gem/dep2@0.15.3"
        },
        {
          "type": "library",
          "group": "",
          "licenses": [{ "license" => { "id" => "MIT" } }],
          "name": "minitest",
          "version": "5.14.4",
          "purl": "pkg:gem/minitest@5.14.4"
        }
      ]
      expect(ruby_cyclonedx.build_components_object).to include(*expected)
    end
  end
end
