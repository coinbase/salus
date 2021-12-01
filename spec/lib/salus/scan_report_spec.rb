require 'spec_helper'

describe Salus::ScanReport do
  let(:scanner_name) { 'T3 Check' }
  let(:failure_message) { 'Please use MAGI to fix' }
  let(:failure_message_two) { 'All too easy' }
  let(:report) { Salus::ScanReport.new(scanner_name, custom_failure_message: failure_message) }

  describe 'merge!' do
    let(:report_two) do
      Salus::ScanReport.new(scanner_name, custom_failure_message: failure_message_two)
    end

    it 'should combine fields' do
      report.record { sleep 0.01 }
      report.log("foo")
      report.warn("sensor", "heat bump")
      report.info("data", "one")
      report.error({ 'Error' => 'Could not check all sectors' })

      report_two.record { sleep 0.10 }
      report_two.log("bar")
      report_two.warn("alarm", "entry")
      report_two.info("info", "two")
      report_two.error({ 'Error' => 'CVE' })

      report.merge!(report_two)
      merged = { scanner_name: "T3 Check",
                passed: true,
                logs: "foo\nbar",
                warn: { "sensor" => "heat bump", "alarm" => "entry" },
                info: { "data" => "one", "info" => "two" },
                errors: [{ "Error" => "Could not check all sectors" }, { "Error" => "CVE" }] }

      report_h = report.to_h
      expect(report_h[:running_time]).to be > 0.1
      # Delete the running time as it will vary slightly per run
      report_h.delete(:running_time)
      expect(report_h).to eq(merged)
    end

    it 'should apply the custom fail message' do
      expect(report.send(:custom_failure_message)).to eq(failure_message)
      report.merge!(report_two)
      expect(report.send(:custom_failure_message)).to eq(failure_message_two)
    end

    it 'will raise when combine reports from different scanners' do
      rpt = Salus::ScanReport.new("Another Scanner")
      error = 'Unable to merge scan reports from different scanners'
      expect { report.merge!(rpt) }.to raise_error(error)
    end
  end

  describe '#to_s' do
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
