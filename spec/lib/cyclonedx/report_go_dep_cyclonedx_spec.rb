require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportGoDep do
  describe "#run" do
    it 'should report all the deps using go.sum if available' do
      repo = Salus::Repo.new('spec/fixtures/report_go_sum')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})
      scanner.run

      golang_cyclonedx = Cyclonedx::ReportGoDep.new(scanner.report)
      expect(golang_cyclonedx.build_components_object[0..1]).to match_array(
        [
          {
            "type": "library",
          "group": "",
            "name": "github.com/davecgh/go-spew",
            "version": "v1.1.0",
            "purl": "pkg:golang/github.com/davecgh/go-spew@v1.1.0"
          },
          {
            "type": "library",
          "group": "",
            "name": "github.com/davecgh/go-spew",
            "version": "v1.1.0",
            "purl": "pkg:golang/github.com/davecgh/go-spew@v1.1.0"
          }
        ]
      )
    end

    it 'should report all the deps in the Gopkg.lock if present' do
      repo = Salus::Repo.new('spec/fixtures/report_go_dep')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})
      scanner.run

      golang_cyclonedx = Cyclonedx::ReportGoDep.new(scanner.report)
      expect(golang_cyclonedx.build_components_object).to match_array(
        [
          {
            "type": "library",
          "group": "",
            "name": "github.com/PagerDuty/go-pagerduty",
            "version": "",
            "purl": "pkg:golang/github.com/PagerDuty/go-pagerduty"
          },
          {
            "type": "library",
          "group": "",
            "name": "github.com/Sirupsen/logrus",
            "version": "v0.11.5",
            "purl": "pkg:golang/github.com/Sirupsen/logrus@v0.11.5"
          },
          {
            "type": "library",
          "group": "",
            "name": "golang.org/x/sys",
            "version": "",
            "purl": "pkg:golang/golang.org/x/sys"
          }
        ]
      )
    end

    let(:listener) { Object.new }
    before(:each) do
      def listener.report_warn(data)
        data
      end
    end

    it 'should report warning and send event if no Gopkg.lock/go.sum' \
    'available and return empty build' do
      repo = Salus::Repo.new('spec/fixtures/report_go_mod')
      Salus::PluginManager.register_listener(listener)

      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})

      expect(listener).to receive(:report_warn).with(
        {
          type: :report_go_dep_missing_go_sum,
          message: 'WARNING: No go.sum/Gopkg.lock found. Currently '\
          'go.mod is unsupported for reporting Golang dependencies.'
        }
      )

      scanner.run

      golang_cyclonedx = Cyclonedx::ReportGoDep.new(scanner.report)
      warnings = scanner.report.to_h.fetch(:warn)

      expect(warnings[:report_go_dep_missing_go_sum]).to eq(
        'WARNING: No go.sum/Gopkg.lock found. Currently go.mod is '\
        'unsupported for reporting Golang dependencies.'
      )
      expect(golang_cyclonedx.build_components_object).to eq([])
    end
  end
end
