require_relative '../../spec_helper'
require 'json'

describe Sarif::CargoAuditSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::CargoAudit.new(repository: repo, config: {}) }
    let(:path) { 'spec/fixtures/cargo_audit/failure-vulnerability-present' }
    before { scanner.run }

    context 'scan report with logged vulnerabilites' do
      let(:repo) { Salus::Repo.new(path) }
      it 'parses information correctly' do
        x = JSON.parse(scanner.report.to_h.fetch(:logs))
        cargo_sarif = Sarif::CargoAuditSarif.new(scanner.report, path)

        issue = x['vulnerabilities']['list'][0]

        expect(cargo_sarif.parse_issue(issue)).to include(
          id: "RUSTSEC-2019-0010",
          name: "MultiDecoder::read() drops uninitialized memory of arbitrary type on panic in"\
          " client code",
          level: "HIGH",
          details: "Affected versions of libflate"\
          " have set a field of an internal structure with a generic type to an uninitialized "\
          "value in `MultiDecoder::read()` and reverted it to the original value after the "\
          "function completed. However, execution of `MultiDecoder::read()` could be interrupted"\
          " by a panic in caller-supplied `Read` implementation. This would cause `drop()` to be"\
          " called on uninitialized memory of a generic type implementing `Read`.\n\nThis is "\
          "equivalent to a use-after-free vulnerability and could allow an attacker to gain "\
          "arbitrary code execution.\n\nThe flaw was corrected by aborting immediately instead of"\
          " unwinding the stack in case of panic within `MultiDecoder::read()`. The issue was "\
          "discovered and fixed by Shnatsel.",
          messageStrings: { "package": { "text": "libflate" },
                          "title": { "text": "MultiDecoder::read() drops uninitialized memory of"\
                          " arbitrary type on panic in client code" },
                          "severity": { "text": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
                          "patched_versions": { "text": "[\">=0.1.25\"]" },
                          "unaffected_versions": { "text": "[\"<0.1.14\"]" } },
          help_url: "https://github.com/sile/libflate/issues/35",
          uri: "Cargo.lock"
        )
      end
    end
  end

  describe '#sarif_report' do
    let(:scanner) { Salus::Scanners::CargoAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'non rust project' do
      let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }
      it 'should handle generated error' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(false)

        message = report_object['invocations'][0]['toolExecutionNotifications'][0]['message']
        expect(message['text']).to include('cargo exited with an unexpected exit status')
      end
    end

    context 'rust project with no vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/cargo_audit/success') }
      it 'should generate an empty sarif report' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]

        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'rust project with empty report containing whitespace' do
      let(:repo) { Salus::Repo.new('spec/fixtures/cargo_audit/success') }
      it 'should handle empty reports with whitespace' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        # Override the report.log() to return "\n"
        report.class.send(:define_method, :log, -> { "\n" })
        expect_any_instance_of(Sarif::CargoAuditSarif).not_to receive(:bugsnag_notify)

        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]
        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'rust project with vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/cargo_audit/failure-vulnerability-present') }
      it 'should generate the right results and rules' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        sarif = JSON.parse(report.to_sarif({ 'include_non_enforced' => true }))
        result = sarif["runs"][0]["results"][0]
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        # Check rule info
        expect(rules[0]['id']).to eq("RUSTSEC-2019-0010")
        expect(rules[0]['name']).to eq("MultiDecoder::read() drops uninitialized memory of"\
          " arbitrary type on panic in client code")
        expect(rules[0]['fullDescription']['text']).to eq("Affected versions of libflate"\
        " have set a field of an internal structure with a generic type to an uninitialized "\
        "value in `MultiDecoder::read()` and reverted it to the original value after the "\
        "function completed. However, execution of `MultiDecoder::read()` could be interrupted"\
        " by a panic in caller-supplied `Read` implementation. This would cause `drop()` to be"\
        " called on uninitialized memory of a generic type implementing `Read`.\n\nThis is "\
        "equivalent to a use-after-free vulnerability and could allow an attacker to gain "\
        "arbitrary code execution.\n\nThe flaw was corrected by aborting immediately instead of"\
        " unwinding the stack in case of panic within `MultiDecoder::read()`. The issue was "\
        "discovered and fixed by Shnatsel.")
        expect(rules[0]['helpUri']).to eq("https://github.com/sile/libflate/issues/35")

        # Check result info
        expect(result['ruleId']).to eq("RUSTSEC-2019-0010")
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('error')
      end
    end
  end

  describe '#sarif_level' do
    it 'parses cargo severity levels to sarif levels' do
      scan_report = Salus::ScanReport.new('CargoAudit')
      scan_report.add_version('0.0.1')
      cargo_sarif = Sarif::CargoAuditSarif.new(scan_report)
      expect(cargo_sarif.sarif_level('HIGH')).to eq('error')
      expect(cargo_sarif.sarif_level('MEDIUM')).to eq('error')
      expect(cargo_sarif.sarif_level('LOW')).to eq('warning')
    end
  end
end
