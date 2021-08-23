require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportGoDep do
  describe "#run" do
    it 'should report all the deps using go.sum if available' do
      repo = Salus::Repo.new('spec/fixtures/report_go_sum')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})
      scanner.run

      golang_cyclonedx = Cyclonedx::ReportGoDep.new(scanner.report)
      expect(golang_cyclonedx.build_components_object[0..2]).to match_array(
        [
          {
            "bom-ref": "pkg:golang/github.cbhq.net/c3/bls12-381",
            "type": "library",
            "group": "",
            "name": "github.cbhq.net/c3/bls12-381",
            "version": "v0.0.0-20210114210818-577bfdc5cb9c",
            "purl": "pkg:golang/github.cbhq.net/c3/bls12-381",
            "properties": [
              {
                "key": "source",
                "value": "N/A for go.mod/go.sum dependencies"
              },
              {
                "key": "dependency_file",
                "value": "go.sum"
              }
            ]
          },
          {
            "bom-ref": "pkg:golang/github.cbhq.net/c3/bls12-381",
            "type": "library",
            "group": "",
            "name": "github.cbhq.net/c3/bls12-381",
            "version": "v0.0.0-20210114210818-577bfdc5cb9c",
            "purl": "pkg:golang/github.cbhq.net/c3/bls12-381",
            "properties": [
              {
                "key": "source",
                "value": "N/A for go.mod/go.sum dependencies"
              },
              {
                "key": "dependency_file",
                "value": "go.sum"
              }
            ]
          },
          {
            "bom-ref": "pkg:golang/github.com/davecgh/go-spew",
            "type": "library",
            "group": "",
            "name": "github.com/davecgh/go-spew",
            "version": "v1.1.0",
            "purl": "pkg:golang/github.com/davecgh/go-spew",
            "properties": [
              {
                "key": "source",
                "value": "N/A for go.mod/go.sum dependencies"
              },
              {
                "key": "dependency_file",
                "value": "go.sum"
              }
            ]
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
            "bom-ref": "pkg:golang/github.com/PagerDuty/go-pagerduty",
            "type": "library",
            "group": "",
            "name": "github.com/PagerDuty/go-pagerduty",
            "version": nil,
            "purl": "pkg:golang/github.com/PagerDuty/go-pagerduty",
            "properties": [
              {
                "key": "source",
                "value": 'fe74e407c23e030fa1523e7cbd972398fd85ec5d'
              },
              {
                "key": "dependency_file",
                "value": "Gopkg.lock"
              }
            ]
          },
          {
            "bom-ref": "pkg:golang/github.com/Sirupsen/logrus",
            "type": "library",
            "group": "",
            "name": "github.com/Sirupsen/logrus",
            "version": "v0.11.5",
            "purl": "pkg:golang/github.com/Sirupsen/logrus",
            "properties": [
              {
                "key": "source",
                "value": 'ba1b36c82c5e05c4f912a88eab0dcd91a171688f'
              },
              {
                "key": "dependency_file",
                "value": "Gopkg.lock"
              }
            ]
          },
          {
            "bom-ref": "pkg:golang/golang.org/x/sys",
            "type": "library",
            "group": "",
            "name": "golang.org/x/sys",
            "version": nil,
            "purl": "pkg:golang/golang.org/x/sys",
            "properties": [
              {
                "key": "source",
                "value": '9a7256cb28ed514b4e1e5f68959914c4c28a92e0'
              },
              {
                "key": "dependency_file",
                "value": "Gopkg.lock"
              }
            ]
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
