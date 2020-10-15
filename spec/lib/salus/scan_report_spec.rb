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
    let(:verbose_string_report) { report.to_s(verbose: true, wrap: 100, use_colors: false) }

    before do
      report.pass
      report.log(log_string)
      report.info(info_type, info_value)
      report.add_version('')
    end

    context 'not verbose and passed' do
      it 'includes all relevant important in string form' do
        expect(string_report).to include('PASSED')
        expect(string_report).not_to include(log_string)
        expect(string_report).not_to include(failure_message)
        expect(string_report).not_to include(info_value)
      end
    end

    context 'not verbose and failed' do
      it 'includes all relevant important in string form' do
        report.fail
        report.error(error_hash)
        expect(string_report).to include('FAILED')
        expect(string_report).to include(log_string)
        expect(string_report).to include(error_hash['Error'])
        expect(string_report).to include(failure_message)
        expect(string_report).not_to include(info_value)
      end
    end

    context 'verbose and passed' do
      it 'includes all relevant important in string form' do
        expect(verbose_string_report).to include('PASSED')
        expect(verbose_string_report).to include(log_string)
        expect(verbose_string_report).to include(info_value)
        expect(verbose_string_report).not_to include(failure_message)
      end
    end

    context 'not verbose' do
      let(:string_report) { report.to_s(verbose: true, wrap: 100, use_colors: false) }

      it 'includes all relevant important in string form' do
        expect(string_report).to include(info_value)
      end
    end
  end
end
