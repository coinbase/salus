require_relative '../../spec_helper.rb'

describe Salus::Report do
  let(:project_name)                    { 'eva00' }
  let(:config_source_1)                 { 'file://./salus.yaml' }
  let(:config_source_2)                 { 'https://salus-config.nerv.net/salus.yaml' }
  let(:config_directive)                { 'active_scanners' }
  let(:config_directive_value)          { 'A, B, C' }
  let(:scanner_1)                       { 'MAGI' }
  let(:scanner_2)                       { 'sync_ratio_check' }
  let(:scanner_1_passed)                { true }
  let(:scanner_2_passed)                { false }
  let(:scanner_1_info_type_1)           { 'detection' }
  let(:scanner_1_info_type_2)           { 'warning' }
  let(:scanner_1_info_type_1_message_1) { 'detected infection' }
  let(:scanner_1_info_type_1_message_2) { 'detected breach' }
  let(:scanner_1_info_type_2_message_1) { 'Casper unit anomaly' }
  let(:scanner_1_stdout)                { 'Operational: C, B, M' }
  let(:scanner_2_stderr)                { 'Cannot scan full ratio.' }
  let(:salus_error_1_class)             { 'EvaError' }
  let(:salus_error_2_class)             { 'SalusRuntime' }
  let(:salus_error_1_data)              { { 'message' => 'Cannot locate EVA02.', 'count' => 2 } }
  let(:salus_error_2_data)              { { 'message' => 'Umbilical cable disconnected.' } }
  let(:salus_runtime_error_data)        { { 'message' => 'Salus died.' } }
  let(:custom_info)                     { 'test unit' }
  let(:report) do
    Salus::Report.new(project_name: project_name, custom_info: custom_info)
  end

  # Load a given report with data.
  def load_report(report)
    report.configuration_source(config_source_1)
    report.configuration_source(config_source_2)
    report.configuration_directive(config_directive, config_directive_value)
    report.scan_passed(scanner_1, scanner_1_passed)
    report.scan_info(scanner_1, scanner_1_info_type_1, scanner_1_info_type_1_message_1)
    report.scan_info(scanner_1, scanner_1_info_type_1, scanner_1_info_type_1_message_2)
    report.scan_info(scanner_1, scanner_1_info_type_2, scanner_1_info_type_2_message_1)
    report.scan_stdout(scanner_1, scanner_1_stdout)
    report.scan_info(scanner_2, scanner_1_info_type_1, scanner_1_info_type_1_message_1)
    report.scan_stderr(scanner_2, scanner_2_stderr)
    report.salus_error(salus_error_1_class, salus_error_1_data)
    report.salus_error(salus_error_2_class, salus_error_2_data)
    report.salus_runtime_error(salus_runtime_error_data)
    report
  end

  let(:loaded_report) { load_report(report) }

  # NOTE: #scan, #info, #error are tested by the construction of the report object above.

  describe '#to_json' do
    it 'should generate a JSON object with expected information' do
      obj = JSON.parse(load_report(report).to_json)
      expect(obj['project_name']).to eq(project_name)
      expect(obj['version']).to eq(Salus::VERSION)
      expect(obj['configuration']).to eq(
        'sources' => [config_source_1, config_source_2],
        config_directive => config_directive_value
      )
      expect(obj['scans']).to include(
        scanner_1 => {
          'passed' => true,
          'info' => {
            scanner_1_info_type_1 => [
              scanner_1_info_type_1_message_1,
              scanner_1_info_type_1_message_2
            ],
            scanner_1_info_type_2 => [
              scanner_1_info_type_2_message_1
            ]
          },
          'stdout' => scanner_1_stdout
        }
      )
      expect(obj['scans']).to include(
        scanner_2 => {
          'info' => {
            scanner_1_info_type_1 => [
              scanner_1_info_type_1_message_1
            ]
          },
          'stderr' => scanner_2_stderr
        }
      )

      expect(obj['errors'][salus_error_1_class]).to include(salus_error_1_data)
      expect(obj['errors'][salus_error_2_class]).to include(salus_error_2_data)
      expect(obj['errors']['Salus']).to include(salus_runtime_error_data)

      expect(obj['custom_info']).to eq(custom_info)
    end
  end

  describe '#to_s' do
    let(:standard_data) do
      [
        project_name,
        scanner_1,
        Salus::Report::SCAN_RESULT_WORD[scanner_1_passed],
        scanner_2,
        scanner_2_stderr,
        salus_error_1_class,
        salus_error_1_data.to_s
      ]
    end
    let(:verbose_data) do
      [
        scanner_1_info_type_1,
        scanner_1_info_type_1_message_1,
        config_source_1,
        config_source_2,
        config_directive,
        config_directive_value
      ]
    end

    context 'verbose: false' do
      it 'should generate text output without info et al.' do
        standard_data.each { |str| expect(loaded_report.to_s(verbose: false)).to include(str) }
        verbose_data.each { |str| expect(loaded_report.to_s(verbose: false)).not_to include(str) }
      end
    end

    context 'verbose: true' do
      it 'should generate text with expected information including info et al.' do
        standard_data.each { |str| expect(loaded_report.to_s(verbose: true)).to include(str) }
        verbose_data.each { |str| expect(loaded_report.to_s(verbose: true)).to include(str) }
      end
    end

    it 'should wrap really long lines' do
      report = Salus::Report.new(
        project_name: 'test project',
        custom_info: 'test unit'
      )

      report.scan_stdout("TestScan", ("A" * 100) + ("B" * 100))

      expect(report.to_s).not_to match(/AAAABBBB/) # Ensure there was a break at 100 chars in
    end
  end

  describe '#export_report' do
    context 'HTTP report URI given' do
      let(:http_report_uri) { 'https://nerv.tk3/salus-report' }
      let(:report_directive) do
        {
          'uri' => http_report_uri,
          'format' => 'json'
        }
      end
      let(:report) do
        Salus::Report.new(
          report_uris: [report_directive],
          project_name: 'eva00',
          custom_info: 'test unit'
        )
      end

      it 'should make a call to send the report for http URI' do
        stub_request(:post, http_report_uri)
          .with(headers: { 'Content-Type' => 'application/json' }, body: loaded_report.to_json)
          .to_return(status: 202)

        expect { loaded_report.export_report }.not_to raise_error

        assert_requested(
          :post,
          http_report_uri,
          headers: { 'Content-Type' => 'application/json' },
          body: loaded_report.to_json,
          times: 1
        )
      end

      it 'should raise if there is an error with sending the report to a HTTP endpoint' do
        stub_request(:post, http_report_uri)
          .with(headers: { 'Content-Type' => 'application/json' }, body: report.to_json)
          .to_return(status: 404)
        expect { report.export_report }.to raise_error(
          Salus::Report::ExportReportError,
          'POST of Salus report to https://nerv.tk3/salus-report had response status 404.'
        )
      end
    end

    context 'local file report URI given' do
      let(:good_file_report_uri) { './spec/fixtures/report/salus_report.json' }
      let(:good_file_report_directive) do
        {
          'uri' => good_file_report_uri,
          'format' => 'json'
        }
      end
      let(:bad_file_report_uri) { './spec/fixtures/non_existent_dir/salus_report.json' }
      let(:bad_file_report_directive) do
        {
          'uri' => bad_file_report_uri,
          'format' => 'json'
        }
      end

      it 'should save to the given directory for a local file uri' do
        # Delete the fixtures file for cleanup - do at start incase last test run failed.
        remove_file(good_file_report_uri)

        report = Salus::Report.new(
          report_uris: [good_file_report_directive],
          project_name: 'eva00',
          custom_info: 'test unit'
        )

        # Save report
        loaded_report = load_report(report)
        loaded_report.export_report

        # Check save
        expect(File.read(good_file_report_uri)).to eq(loaded_report.to_json)

        # Delete the fixtures file for cleanup.
        remove_file(good_file_report_uri)
      end

      it 'should raise if it tries to write a file report to a non-existent directory' do
        report = Salus::Report.new(
          report_uris: [bad_file_report_directive],
          project_name: 'eva00',
          custom_info: 'test unit'
        )
        expect { report.export_report }.to raise_error(
          Salus::Report::ExportReportError,
          "Cannot write file #{bad_file_report_uri} - " \
          "Errno::ENOENT: No such file or directory @ rb_sysopen - "      \
          "./spec/fixtures/non_existent_dir/salus_report.json"
        )
      end
    end
  end
end
