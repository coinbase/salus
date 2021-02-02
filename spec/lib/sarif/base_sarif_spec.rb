require_relative '../../spec_helper.rb'
require 'json-schema'

describe Sarif::BaseSarif do
  let(:scan_report) { Salus::ScanReport.new("Bandit") }
  let(:base_sarif) { Sarif::BaseSarif.new(scan_report) }

  before do
    scan_report.add_version('1.1.1')
  end

  describe 'sarif_report' do
    it 'returns the runs object for an unsupported scanner' do
      schema = JSON.parse(File.read('spec/fixtures/sarif/sarif-schema.json'))
      body = JSON.pretty_generate({ "version" => "2.1.0",
        "$schema" => "https://schemastore.azurewebsites.net/schemas"\
        "/json/sarif-2.1.0-rtm.5.json",
        "runs" => [base_sarif.sarif_report] })
      expect(JSON::Validator.validate(schema, JSON.parse(body))).to be true
    end
  end
end
