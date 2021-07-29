require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportRubyGems do
  describe "#run" do
    it 'should report all the deps in the Gemfile if Gemfile.lock is absent in cyclonedx' do
      repo = Salus::Repo.new('spec/fixtures/report_ruby_gems/gemfile_only')
      scanner = Salus::Scanners::ReportRubyGems.new(repository: repo, config: {})
      scanner.run

      ruby_cyclonedx = Cyclonedx::ReportRubyGems.new(scanner.report)
      expect(ruby_cyclonedx.build_components_object).to match_array(
        [
          {
            "bom-ref": "pkg:gem/kibana_url",
            "type": "library",
            "group": "",
            "name": "kibana_url",
            "version": "~> 1.0",
            "purl": "pkg:gem/kibana_url",
            "properties": [
              {
                "key": "source",
                "value": "https://rubygems.org/"
              },
              {
                "key": "dependency_file",
                "value": "Gemfile"
              }
            ]
          },
          {
            "bom-ref": "pkg:gem/rails",
            "type": "library",
            "group": "",
            "name": "rails",
            "version": ">= 0",
            "purl": "pkg:gem/rails",
            "properties": [
              {
                "key": "source",
                "value": "https://rubygems.org/"
              },
              {
                "key": "dependency_file",
                "value": "Gemfile"
              }
            ]
          },
          {
            "bom-ref": "pkg:gem/master_lock",
            "type": "library",
            "group": "",
            "name": "master_lock",
            "version": ">= 0",
            "purl": "pkg:gem/master_lock",
            "properties": [
              {
                "key": "source",
                "value": "git@github.com:coinbase/master_lock.git"
              },
              {
                "key": "dependency_file",
                "value": "Gemfile"
              }
            ]
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
          "bom-ref": "pkg:gem/actioncable@5.1.2",
          "type": "library",
          "group": "",
          "name": "actioncable",
          "version": "5.1.2",
          "purl": "pkg:gem/actioncable@5.1.2",
          "properties": [
            {
              "key": "source",
              "value": "rubygems repository https://rubygems.org/ or installed locally"
            },
            {
              "key": "dependency_file",
              "value": "Gemfile.lock"
            }
          ]
        },
        {
          "bom-ref": "pkg:gem/actionmailer@5.1.2",
          "type": "library",
          "group": "",
          "name": "actionmailer",
          "version": "5.1.2",
          "purl": "pkg:gem/actionmailer@5.1.2",
          "properties": [
            {
              "key": "source",
              "value": "rubygems repository https://rubygems.org/ or installed locally"
            },
            {
              "key": "dependency_file",
              "value": "Gemfile.lock"
            }
          ]
        },
        {
          "bom-ref": "pkg:gem/kibana_url@1.0.1",
          "type": "library",
          "group": "",
          "name": "kibana_url",
          "version": "1.0.1",
          "purl": "pkg:gem/kibana_url@1.0.1",
          "properties": [
            {
              "key": "source",
              "value": "rubygems repository https://rubygems.org/ or installed locally"
            },
            {
              "key": "dependency_file",
              "value": "Gemfile.lock"
            }
          ]
        },
        {
          "bom-ref": "pkg:gem/master_lock@0.9.1",
          "type": "library",
          "group": "",
          "name": "master_lock",
          "version": "0.9.1",
          "purl": "pkg:gem/master_lock@0.9.1",
          "properties": [
            {
              "key": "source",
              "value": "git@github.com:coinbase/master_lock.git"
            },
            {
              "key": "dependency_file",
              "value": "Gemfile.lock"
            }
          ]
        }
      ]
      expect(ruby_cyclonedx.build_components_object).to include(*expected)
    end
  end
end
