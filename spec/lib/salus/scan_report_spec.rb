require 'spec_helper'

describe Salus::ScanReport do
  describe '#to_s' do
    let(:scanner_name) { 'T3 Check' }
    let(:failure_message) { 'Please use MAGI to fix' }
    let(:report) { Salus::ScanReport.new(scanner_name, custom_failure_message: failure_message) }
    let(:log_string) { 'Checking underground bunkers.' }
    let(:info_type) { 'LockStatus' }
    let(:info_value) { 'Locked' }
    let(:error_hash) { { 'Error' => 'Could not check all sectors' } }
    let(:string_report) { report.to_s(verbose: false, wrap: 100, use_colors: false) }

    before do
      report.fail
      report.log(log_string)
      report.info(info_type, info_value)
      report.error(error_hash)
    end

    context 'not verbose' do
      it 'includes all relevant improtant in string form' do
        expect(string_report).to include('FAILED')
        expect(string_report).to include(log_string)
        expect(string_report).to include(error_hash['Error'])
        expect(string_report).to include(failure_message)
        expect(string_report).not_to include(info_value)
      end
    end

    context 'not verbose' do
      let(:string_report) { report.to_s(verbose: true, wrap: 100, use_colors: false) }

      it 'includes all relevant improtant in string form' do
        expect(string_report).to include(info_value)
      end
    end
  end
end
