require_relative '../../spec_helper.rb'
require 'yaml'

describe Salus::Report do
  let(:report) { build_report }
  let(:scan_reports) { (0...3).map { build_scan_report } }
  SALUS_VERSION = Salus::VERSION

  describe '#to_s' do
    it 'should merge runs from the same scanner' do
      report = Salus::Report.new(merge_by_scanner: true)
      (0...5).each do |i|
        scan_report = Salus::ScanReport.new('DerpScanner')
        i == 0 ? scan_report.fail : scan_report.pass
        report.add_scan_report(scan_report, required: true)
      end

      to_s = "==== Salus Scan v#{SALUS_VERSION}\n\n" \
        "==== DerpScanner: FAILED\n\n" \
        "==== Salus Configuration Files Used:\n\n\n\n" \
        "Overall scan status: FAILED\n\n" \
        "┌─────────────┬──────────────┬──────────┬────────┐\n" \
        "│ Scanner     │ Running Time │ Required │ Passed │\n" \
        "├─────────────┼──────────────┼──────────┼────────┤\n" \
        "│ DerpScanner │ 0s           │ yes      │ no     │\n" \
        "└─────────────┴──────────────┴──────────┴────────┘"
      expect(report.to_s).to eq(to_s)
    end
  end

  describe '#to_h and miscellaneous reporting methods' do
    it 'emits the expected reporting data via the #to_h method' do
      name = 'Neon Genesis Evangelion'
      custom_info = { bitcoin_price: 100_000 }
      config = { lemurs: 'contained', raptors: 'loose' }

      report = Salus::Report.new(project_name: name, custom_info: custom_info, config: config)

      # The actual content here doesn't really matter -
      # that functionality is speced out in the ScanReport unit tests
      scan_reports = (1..5).map do |index|
        scan_report = Salus::ScanReport.new("Scanner#{index}")
        scan_report.info(:safe, 'maybe')
        scan_report.error(message: 'something amiss')
        scan_report.dependency(dependency_file: 'libxml2.so.2')
        scan_report.pass
        scan_report
      end

      scan_reports.each { |scan_report| report.add_scan_report(scan_report, required: false) }

      (1..5).map { |index| report.error(message: 'some top-level error', data: index) }

      hsh = report.to_h

      expect(hsh.fetch(:project_name)).to eq(name)
      expect(hsh.fetch(:custom_info)).to eq(custom_info)
      expect(hsh.fetch(:config)).to eq(config)

      hsh.fetch(:errors).each do |error|
        expect(error[:message]).to eq('some top-level error')
        expect((1..5)).to cover(error[:data])
      end

      scans = hsh.fetch(:scans)

      expectation =
        scan_reports
          .map { |scan_report, _required| [scan_report.scanner_name, scan_report.to_h] }
          .to_h

      expect(scans).to eq(expectation)
    end

    it 'should apply filters for to_h' do
      report = Salus::Report.new
      allow(report).to receive(:apply_report_hash_filters).and_wrap_original do |_method, arg|
        arg[:version]
      end
      expect(report).to receive(:apply_report_hash_filters)
      expect(report.to_h).to eq(Salus::VERSION)
    end

    it 'should apply filters for to_sarif' do
      report = Salus::Report.new
      allow(report).to receive(:apply_report_sarif_filters).and_wrap_original do |_method, arg|
        sarif = JSON.parse(arg)
        sarif["$schema"] = "foo"
        sarif.to_json
      end
      expect(report).to receive(:apply_report_sarif_filters)
      sarif = report.to_sarif
      expect(sarif).to eq('{"$schema":"foo","runs":[],"version":"2.1.0"}')
    end

    it 'does not include project_name/custom_info/config if not given' do
      report = Salus::Report.new
      hsh = report.to_h
      expect(hsh.key?(:project_name)).to eq(false)
      expect(hsh.key?(:custom_info)).to eq(false)
      expect(hsh.key?(:config)).to eq(false)
    end

    it 'should merge multilpe scans from a given scanner, failing if any failed' do
      report = Salus::Report.new(merge_by_scanner: true)
      (0...5).each do |i|
        scan_report = Salus::ScanReport.new('DerpScanner')
        i == 0 ? scan_report.fail : scan_report.pass
        report.add_scan_report(scan_report, required: true)
      end

      to_h = { version: Salus::VERSION, passed: false,
        scans: {
          "DerpScanner" => { scanner_name: "DerpScanner",
                             passed: false,
                             warn: {},
                             info: {},
                             errors: [] }
        },
        errors: [] }

      expect(report.to_h).to eq(to_h)
    end
  end

  describe '#passed?' do
    it 'returns true if and only if all required scans passed' do
      passed_scan_reports = (0...5).map do
        scan_report = Salus::ScanReport.new('DerpScanner')
        scan_report.pass
        scan_report
      end

      failed_scan_reports = (0...5).map do
        scan_report = Salus::ScanReport.new('HerpScanner')
        scan_report.fail
        scan_report
      end

      # No scans; passed
      report = Salus::Report.new
      expect(report.passed?).to eq(true)

      # All scans required; all passed
      report = Salus::Report.new
      passed_scan_reports.each do |scan_report|
        report.add_scan_report(scan_report, required: true)
      end
      expect(report.passed?).to eq(true)

      # All scans not required; all passed
      report = Salus::Report.new
      passed_scan_reports.each do |scan_report|
        report.add_scan_report(scan_report, required: false)
      end
      expect(report.passed?).to eq(true)

      # All scans required; all failed
      report = Salus::Report.new
      failed_scan_reports.each do |scan_report|
        report.add_scan_report(scan_report, required: true)
      end
      expect(report.passed?).to eq(false)

      # All scans not required; all failed
      report = Salus::Report.new
      failed_scan_reports.each do |scan_report|
        report.add_scan_report(scan_report, required: false)
      end
      expect(report.passed?).to eq(true)

      # All scans required; several passed scans but one failed scan
      report = Salus::Report.new
      report.add_scan_report(failed_scan_reports[0], required: true)
      passed_scan_reports.each do |scan_report|
        report.add_scan_report(scan_report, required: true)
      end
      expect(report.passed?).to eq(false)

      # Mix of required and un-required scans; all failed scans not required
      report = Salus::Report.new
      (passed_scan_reports + failed_scan_reports).each do |scan_report|
        required = scan_report.passed? && rand < 0.5
        report.add_scan_report(scan_report, required: required)
      end
      expect(report.passed?).to eq(true)
    end
  end

  describe '#export_report' do
    def build_report(report_uri)
      report = Salus::Report.new(
        report_uris: [report_uri],
        project_name: 'eva00',
        custom_info: 'test unit'
      )

      3.times do
        scan_report = Salus::ScanReport.new('DerpScanner')
        scan_report.info(:asdf, 'qwerty')
        scan_report.fail
        report.add_scan_report(scan_report, required: true)
      end

      5.times { report.error(message: 'derp') }

      report
    end

    context 'HTTP report URI given' do
      it 'should make a call to send the report for http URI' do
        url = 'https://nerv.tk3/salus-report'
        directive = { 'uri' => url, 'format' => 'json' }
        report = build_report(directive)

        stub_request(:post, url)
          .with(headers: { 'Content-Type' => 'application/json' }, body: report.to_json)
          .to_return(status: 202)

        expect { report.export_report }.not_to raise_error

        assert_requested(
          :post,
          url,
          headers: { 'Content-Type' => 'application/json' },
          body: report.to_json,
          times: 1
        )
      end

      it 'should raise if there is an error with sending the report to a HTTP endpoint' do
        url = 'https://nerv.tk3/salus-report'
        directive = { 'uri' => url, 'format' => 'json' }
        report = build_report(directive)

        stub_request(:post, url)
          .with(headers: { 'Content-Type' => 'application/json' }, body: report.to_json)
          .to_return(status: 404)

        expect { report.export_report }.to raise_error(
          Salus::Report::ExportReportError,
          'Salus report to https://nerv.tk3/salus-report had response status 404.'
        )
      end
    end

    context 'HTTP report URI given with request parameters' do
      it 'should make a call to send the json report for http URI' do
        url = 'https://nerv.tk3/salus-report'
        params = { 'salus_report_param_name' => 'report',
          'additional_params' => { "foo" => "bar", "abc" => "def" } }
        directive = { 'uri' => url, 'format' => 'json',
                      'post' => params }
        report = build_report(directive)

        stub_request(:post, "https://nerv.tk3/salus-report")
          .with(
            body: "{\n  \"foo\": \"bar\",\n  \"abc\": \"def\",\n  \"report\": {\n    "\
           "\"custom_info\": \"test unit\",\n    \"errors\": [\n      {\n        "\
           "\"message\": \"derp\"\n      },\n      {\n        \"message\": \"derp\"\n      },\n"\
           "      {\n        \"message\": \"derp\"\n      },\n      {\n        \"message\": "\
           "\"derp\"\n      },\n      {\n        \"message\": \"derp\"\n      }\n    ],\n    "\
           "\"passed\": false,\n    \"project_name\": \"eva00\",\n    \"scans\": {\n      "\
           "\"DerpScanner\": {\n        \"errors\": [\n\n        ],\n        \"info\": {\n     "\
           "     \"asdf\": \"qwerty\"\n        },\n        \"passed\": false,\n        "\
           "\"scanner_name\": \"DerpScanner\",\n        \"warn\": {\n        }\n      }\n    "\
           "},\n    \"version\": \"#{SALUS_VERSION}\"\n  }\n}",
           headers: { 'Accept' => '*/*',
          'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
          'Content-Type' => 'application/json',
          'User-Agent' => 'Faraday v1.3.0',
          'X-Scanner' => 'salus' }
          ).to_return(status: 200, body: "", headers: {})

        expect { report.export_report }.not_to raise_error
      end

      it 'should make a call to send the yaml report for http URI' do
        url = 'https://nerv.tk3/salus-report'
        params = { 'salus_report_param_name' => 'report',
          'additional_params' => { "foo" => "bar", "abc" => "def" } }
        directive = { 'uri' => url, 'format' => 'yaml', 'post' => params }
        report = build_report(directive)

        stub_request(:post, "https://nerv.tk3/salus-report")
          .with(body: "---\nfoo: bar\nabc: def\nreport:\n  :custom_info: test unit\n  :errors:\n  "\
            "- :message: derp\n  - :message: derp\n  - :message: derp\n  - :message: derp\n  - "\
            ":message: derp\n  :passed: false\n  :project_name: eva00\n  :scans:\n    DerpScanner:"\
            "\n      :errors: []\n      :info:\n        :asdf: qwerty\n      :passed: false\n     "\
            " :scanner_name: DerpScanner\n      :warn: {}\n  :version: #{SALUS_VERSION}\n",
           headers: { 'Accept' => '*/*',
          'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
          'Content-Type' => 'text/x-yaml',
          'User-Agent' => 'Faraday v1.3.0',
          'X-Scanner' => 'salus' }).to_return(status: 200, body: "", headers: {})
        expect { report.export_report }.not_to raise_error
      end

      it 'should make a call to send the txt report for http URI' do
        url = 'https://nerv.tk3/salus-report'
        params = { 'salus_report_param_name' => 'report',
          'additional_params' => { "foo" => "bar", "abc" => "def" } }
        directive = { 'uri' => url, 'format' => 'txt', 'post' => params, 'verbose': false }
        report = build_report(directive)
        report.instance_variable_set(:@scan_reports, [])
        config = { 'sources' => { 'valid' => ['word'] } }.deep_symbolize_keys
        report.instance_variable_set(:@config, config)

        stub_request(:post, "https://nerv.tk3/salus-report").with(body: "{\"foo\"=>\"bar\", \"abc"\
          "\"=>\"def\", \"report\"=>\"==== Salus Scan v#{SALUS_VERSION} for eva00\\n\\n==== Salus "\
          "Configuration Files Used:\\n\\n  word\\n\\n\\n==== Salus Errors\\n\\n  [\\n    {\\n    "\
          "  \\\"message\\\": \\\"derp\\\"\\n    },\\n    {\\n      \\\"message\\\": \\\"derp\\"\
          "\"\\n    },\\n    {\\n      \\\"message\\\": \\\"derp\\\"\\n    },\\n    {\\n      "\
          "\\\"message\\\": \\\"derp\\\"\\n    },\\n    {\\n      \\\"message\\\": \\\"derp\\\"\\n"\
          "    }\\n  ]\\n\\n\\nOverall scan status: PASSED\\n\\n┌─────────┬──────────────┬────────"\
          "──┬────────┐\\n│ Scanner │ Running Time │ Required │ Passed │\\n├─────────┼────────────"\
          "──┼──────────┼────────┤\\n\\n└─────────┴──────────────┴──────────┴────────┘\"}",
          headers: { 'Accept' => '*/*',
          'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
          'Content-Type' => 'text/plain',
          'User-Agent' => 'Faraday v1.3.0',
          'X-Scanner' => 'salus' }).to_return(status: 200, body: "", headers: {})
        expect { report.export_report }.not_to raise_error
      end

      it 'should make a call to send the sarif report for http URI' do
        url = 'https://nerv.tk3/salus-report'
        params = { 'salus_report_param_name' => 'report',
          'additional_params' => { "foo" => "bar", "abc" => "def" } }
        options = { 'foo' => 'bar' }
        directive = { 'uri' => url, 'format' => 'sarif', 'post' => params,
                      'verbose': false, 'sarif_options' => options }
        report = build_report(directive)
        report.instance_variable_set(:@scan_reports, [])

        stub_request(:post, "https://nerv.tk3/salus-report")
          .with(
            body: "{\n  \"foo\": \"bar\",\n  \"abc\": \"def\",\n  \"report\": {\n    \"$schema\":"\
            " \"https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/schemas/sarif-schema-2.1.0"\
            "\",\n    \"runs\": [\n\n    ],\n    \"version\": \"2.1.0\"\n  }\n}",
            headers: { 'Accept' => '*/*',
              'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
              'Content-Type' => 'application/json',
              'User-Agent' => 'Faraday v1.3.0',
              'X-Scanner' => 'salus_sarif' }
          ).to_return(status: 200, body: "", headers: {})

        expect(report).to receive(:to_sarif).with(options).and_call_original.twice
        expect { report.export_report }.not_to raise_error
      end

      it 'should make a call to send the sarif_diff_full report for http URI' do
        url = 'https://nerv.tk3/salus-report'
        params = { 'salus_report_param_name' => 'report',
          'additional_params' => { "foo" => "bar", "abc" => "def" } }
        options = { 'foo' => 'bar' }
        directive = { 'uri' => url, 'format' => 'sarif_diff_full', 'post' => params,
                      'verbose': false, 'sarif_options' => options }
        report = build_report(directive)
        report.instance_variable_set(:@scan_reports, [])
        content = { "version": "2.1.0",
                    "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/" \
                               "schemas/sarif-schema-2.1.0",
                "runs": [] }
        report.instance_variable_set(:@full_diff_sarif, content)

        stub_request(:post, "https://nerv.tk3/salus-report").with(
          body: "{\n  \"foo\": \"bar\",\n  \"abc\": \"def\",\n  \"report\": {\n    \"version\": "\
          "\"2.1.0\",\n    \"$schema\": \"https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/"\
          "schemas/sarif-schema-2.1.0\",\n    \"runs\": [\n\n    ]\n  }\n}",
          headers: { 'Accept' => '*/*',
            'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
            'Content-Type' => 'application/json',
            'User-Agent' => 'Faraday v1.3.0',
            'X-Scanner' => 'salus_sarif' }
        ).to_return(status: 200, body: "", headers: {})

        expect(report).to receive(:to_full_sarif_diff).and_call_original.twice
        expect { report.export_report }.not_to raise_error
      end
    end

    context 'local file report URI given' do
      it 'should save to the given directory for a local file uri' do
        path = './spec/fixtures/report/salus_report.json'
        directive = { 'uri' => path, 'format' => 'json' }
        report = build_report(directive)

        # Delete the fixtures file for cleanup - do at start incase last test run failed.
        remove_file(path)

        # Save report
        report.export_report

        # Check save
        expect(File.read(path)).to eq(report.to_json)

        # Delete the fixtures file for cleanup.
        remove_file(path)
      end

      it 'should raise if it tries to write a file report to a non-existent directory' do
        path = './spec/fixtures/non_existent_dir/salus_report.json'
        directive = { 'uri' => path, 'format' => 'json' }
        report = report = build_report(directive)

        report = Salus::Report.new(
          report_uris: [directive],
          project_name: 'eva00',
          custom_info: 'test unit'
        )

        expect { report.export_report }.to raise_error(
          Salus::Report::ExportReportError,
          "Cannot write file #{path} - " \
          "Errno::ENOENT: No such file or directory @ rb_sysopen - "      \
          "./spec/fixtures/non_existent_dir/salus_report.json"
        )
      end
    end

    context 'x-scanner type' do
      it 'should get the correct x-scanner based on format' do
        report = Salus::ReportRequest
        expect(report.x_scanner_type('json')).to eq('salus')
        expect(report.x_scanner_type('yaml')).to eq('salus')
        expect(report.x_scanner_type('sarif_diff')).to eq('salus_sarif_diff')
        expect(report.x_scanner_type('sarif')).to eq('salus_sarif')
        expect(report.x_scanner_type('sarif_diff_full')).to eq('salus_sarif')
      end
    end
  end

  describe 'merge_reports' do
    it 'should merge reports from the same scanner when configured' do
      path = './spec/fixtures/non_existent_dir/salus_report.json'
      report = Salus::Report.new(
        report_uris: [{ 'uri' => path, 'format' => 'json' }],
        project_name: 'eva00',
        custom_info: 'test unit',
        report_filter: nil,
        merge_by_scanner: true
      )

      3.times do
        scan_report = Salus::ScanReport.new('DerpScanner')
        scan_report.info(:asdf, 'qwerty')
        scan_report.fail
        report.add_scan_report(scan_report, required: true)
      end

      5.times { report.error(message: 'derp') }

      expect(report.instance_variable_get(:@scan_reports).size).to eq(3)
      expect(report.merged_reports.size).to eq(1)
    end

    it 'should not merge reports from the same scanner by default' do
      path = './spec/fixtures/non_existent_dir/salus_report.json'
      report = Salus::Report.new(
        report_uris: [{ 'uri' => path, 'format' => 'json' }],
        project_name: 'eva00',
        custom_info: 'test unit',
        report_filter: nil
      )

      3.times do
        scan_report = Salus::ScanReport.new('DerpScanner')
        scan_report.info(:asdf, 'qwerty')
        scan_report.fail
        report.add_scan_report(scan_report, required: true)
      end

      5.times { report.error(message: 'derp') }

      expect(report.instance_variable_get(:@scan_reports).size).to eq(3)
      expect(report.merged_reports.size).to eq(3)
    end
  end

  describe '#satisfies_filter' do
    def build_report(report_uris, filter)
      report = Salus::Report.new(
        report_uris: report_uris,
        project_name: 'eva00',
        custom_info: 'test unit',
        report_filter: filter
      )

      3.times do
        scan_report = Salus::ScanReport.new('DerpScanner')
        scan_report.info(:asdf, 'qwerty')
        scan_report.fail
        report.add_scan_report(scan_report, required: true)
      end

      5.times { report.error(message: 'derp') }

      report
    end

    it 'runs all reports when `all` filter is provided' do
      http_url_one = 'https://nerv.tk3/salus-report'
      http_url_two = 'https://nerv.tk4/salus-report2'
      file_path = './spec/fixtures/report/salus_report.json'
      directives = [
        { 'uri' => http_url_one, 'format' => 'json' },
        { 'uri' => file_path, 'format' => 'json' },
        { 'uri' => http_url_two, 'format' => 'json' }
      ]
      report = build_report(
        directives,
        'all'
      )

      stub_request(:post, http_url_one)
        .with(headers: { 'Content-Type' => 'application/json' }, body: report.to_json)
        .to_return(status: 202)
      stub_request(:post, http_url_two)
        .with(headers: { 'Content-Type' => 'application/json' }, body: report.to_json)
        .to_return(status: 202)

      report.export_report

      assert_requested(
        :post,
        http_url_one,
        headers: { 'Content-Type' => 'application/json' },
        body: report.to_json,
        times: 1
      )
      assert_requested(
        :post,
        http_url_two,
        headers: { 'Content-Type' => 'application/json' },
        body: report.to_json,
        times: 1
      )

      expect(File.exist?(file_path)).to eq(true)

      remove_file(file_path)
    end

    it 'doesnt run any reports when `none` filter is provided' do
      http_url_one = 'https://nerv.tk3/salus-report'
      http_url_two = 'https://nerv.tk4/salus-report2'
      file_path = './spec/fixtures/report/salus_report.json'
      directives = [
        { 'uri' => http_url_one, 'format' => 'json' },
        { 'uri' => file_path, 'format' => 'json' },
        { 'uri' => http_url_two, 'format' => 'json' }
      ]
      report = build_report(
        directives,
        'none'
      )

      stub_request(:post, http_url_one)
        .with(headers: { 'Content-Type' => 'application/json' }, body: report.to_json)
        .to_return(status: 202)
      stub_request(:post, http_url_two)
        .with(headers: { 'Content-Type' => 'application/json' }, body: report.to_json)
        .to_return(status: 202)

      report.export_report

      assert_requested(
        :post,
        http_url_one,
        headers: { 'Content-Type' => 'application/json' },
        body: report.to_json,
        times: 0
      )
      assert_requested(
        :post,
        http_url_two,
        headers: { 'Content-Type' => 'application/json' },
        body: report.to_json,
        times: 0
      )
      expect(File.exist?(file_path)).to eq(false)
    end

    it 'runs only `good-name` reports when `name:good-name` filter is provided' do
      http_url_one = 'https://nerv.tk3/salus-report'
      http_url_two = 'https://nerv.tk4/salus-report2'
      file_path = './spec/fixtures/report/salus_report.json'
      directives = [
        { 'uri' => http_url_one, 'format' => 'json', 'name' => 'good-name' },
        { 'uri' => file_path, 'format' => 'json', 'name' => 'good-name' },
        { 'uri' => http_url_two, 'format' => 'json', 'name' => 'bad-name' }
      ]
      report = build_report(
        directives,
        'name:good-name'
      )

      stub_request(:post, http_url_one)
        .with(headers: { 'Content-Type' => 'application/json' }, body: report.to_json)
        .to_return(status: 202)
      stub_request(:post, http_url_two)
        .with(headers: { 'Content-Type' => 'application/json' }, body: report.to_json)
        .to_return(status: 202)

      report.export_report

      assert_requested(
        :post,
        http_url_one,
        headers: { 'Content-Type' => 'application/json' },
        body: report.to_json,
        times: 1
      )
      assert_requested(
        :post,
        http_url_two,
        headers: { 'Content-Type' => 'application/json' },
        body: report.to_json,
        times: 0
      )
      expect(File.exist?(file_path)).to eq(true)
      remove_file(file_path)
    end

    it 'runs only yaml-formatted reports when `format:yaml` filter is provided' do
      http_url_one = 'https://nerv.tk3/salus-report'
      http_url_two = 'https://nerv.tk4/salus-report2'
      file_path = './spec/fixtures/report/salus_report.json'
      directives = [
        { 'uri' => http_url_one, 'format' => 'yaml' },
        { 'uri' => file_path, 'format' => 'json' },
        { 'uri' => http_url_two, 'format' => 'yaml' }
      ]
      report = build_report(
        directives,
        'format:yaml'
      )

      stub_request(:post, http_url_one)
        .with(headers: { 'Content-Type' => 'text/x-yaml' }, body: report.to_yaml)
        .to_return(status: 202)
      stub_request(:post, http_url_two)
        .with(headers: { 'Content-Type' => 'text/x-yaml' }, body: report.to_yaml)
        .to_return(status: 202)

      report.export_report

      assert_requested(
        :post,
        http_url_one,
        headers: { 'Content-Type' => 'text/x-yaml' },
        body: report.to_yaml,
        times: 1
      )
      assert_requested(
        :post,
        http_url_two,
        headers: { 'Content-Type' => 'text/x-yaml' },
        body: report.to_yaml,
        times: 1
      )
      expect(File.exist?(file_path)).to eq(false)
    end

    it 'runs only reports with `name` keys when `name:*` filter is provided' do
      http_url_one = 'https://nerv.tk3/salus-report'
      http_url_two = 'https://nerv.tk4/salus-report2'
      file_path = './spec/fixtures/report/salus_report.json'
      directives = [
        { 'uri' => http_url_one, 'format' => 'yaml', 'name' => 'alpha' },
        { 'uri' => http_url_two, 'format' => 'json', 'name' => 'alpha' },
        { 'uri' => file_path, 'format' => 'yaml' }
      ]
      report = build_report(
        directives,
        'name:*'
      )

      stub_request(:post, http_url_one)
        .with(headers: { 'Content-Type' => 'text/x-yaml' }, body: report.to_yaml)
        .to_return(status: 202)
      stub_request(:post, http_url_two)
        .with(headers: { 'Content-Type' => 'application/json' }, body: report.to_json)
        .to_return(status: 202)

      report.export_report

      assert_requested(
        :post,
        http_url_one,
        headers: { 'Content-Type' => 'text/x-yaml' },
        body: report.to_yaml,
        times: 1
      )
      assert_requested(
        :post,
        http_url_two,
        headers: { 'Content-Type' => 'application/json' },
        body: report.to_json,
        times: 1
      )
      expect(File.exist?(file_path)).to eq(false)
    end
  end

  describe '#deep_sort' do
    before :all do
      @reports = build_report
    end

    def build_report
      report = Salus::Report.new(project_name: 'Neon genesis')
      config = {
        "matches" => [
          {
            "pattern" => "1 == $X",
            "language" => "python",
            "message" => "Useless equality test.",
            "required" => true
          }
        ]
      }
      repo = Salus::Repo.new("spec/fixtures/semgrep")
      scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
      scanner.run

      report.add_scan_report(scanner.report, required: true)

      path2 = Salus::Repo.new('spec/fixtures/bundle_audit/no_cves')
      scanner = Salus::Scanners::BundleAudit.new(repository: path2, config: {})
      scanner.run
      report.add_scan_report(scanner.report, required: false)

      path = Salus::Repo.new('spec/fixtures/python/python_project_no_vulns')
      scanner = Salus::Scanners::Bandit.new(repository: path, config: {})
      scanner.run
      report.add_scan_report(scanner.report, required: false)
      report
    end

    context 'for salus outputs' do
      let(:results_dir) { 'spec/fixtures/sorted_results' }
      it 'should deepsort json output format' do
        expected_result = File.read("#{results_dir}/sorted_json.json")
        sorted_json = report.to_json
        expect(expected_result).to eq(sorted_json)
      end

      it 'should deepsort sarif output' do
        expected_result = File.read("#{results_dir}/sorted_sarif.json")
        sorted_sarif = JSON.parse(report.to_sarif)
        sorted_sarif['runs'].each do |result|
          # PROJECTROOT was taken out because it has the users local directory in the result json
          # This could cause tests to fail, when run on different machines
          result['originalUriBaseIds'].delete('PROJECTROOT')
        end
        expect(expected_result).to eq(JSON.pretty_generate(sorted_sarif))
      end

      it 'should deepsort YAML output' do
        expected_yaml = File.read("#{results_dir}/sorted_yaml.yml")
        expected_yaml.slice!("---\n")
        result = report.to_yaml
        result.slice!("---\n")
        # Prevent whitespace issues by
        # formatting both values identically
        result = YAML.safe_load(result).to_s
        expected_yaml = YAML.safe_load(expected_yaml).to_s

        expect(expected_yaml).to eq(result)
      end

      it 'should deepsort cyclonedx output' do
        cyclonedx = JSON.parse(report.to_cyclonedx)
        bom = JSON.parse(Base64.strict_decode64(cyclonedx['bom']))
        bom['serialNumber'] = '' # serial number changes with each run
        cyclonedx['bom'] = '' # encoding for bom changes with each run

        # Check Cyclonedx output is sorted
        expected_cyclone = File.read("#{results_dir}/sorted_cyclonedx.json")
        expect(expected_cyclone).to eq(JSON.pretty_generate(cyclonedx))

        # Check cyclondx bom is also sorted
        expected_cyclone_bom = File.read("#{results_dir}/sorted_bom.json")
        expect(expected_cyclone_bom).to eq(JSON.pretty_generate(bom))
      end
    end
  end
end
