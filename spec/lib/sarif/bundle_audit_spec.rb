require_relative '../../spec_helper.rb'

describe Sarif::BundleAuditSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::BundleAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'scan report with logged vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/bundle_audit/cves_found') }
      it 'parses information correctly' do
        bundle_audit_sarif = Sarif::BundleAuditSarif.new(scanner.report)
        issue = scanner.report.to_h[:info][:vulnerabilities][0]

        # should Parse and fill out hash
        expected = "It is possible to possible to, given a global CSRF token such as the"\
        " one\npresent in the authenticity_token meta tag, forge a per-form CSRF token for\nany"\
        " action for that session.\n\nVersions Affected:  rails < 5.2.5, rails < 6.0.4\nNot"\
        " affected:       Applications without existing HTML injection vulnerabilities.\nFixed"\
        " Versions:     rails >= 5.2.4.3, rails >= 6.0.3.1\n\nImpact\n------\n\nGiven the ability"\
        " to extract the global CSRF token, an attacker would be able to\nconstruct a per-form"\
        " CSRF token for that session.\n\nWorkarounds\n-----------\n\nThis is a low-severity"\
        " security issue. As such, no workaround is necessarily\nuntil such time as the"\
        " application can be upgraded.\n"

        expect(bundle_audit_sarif.parse_issue(issue)).to include(
          id: "CVE-2020-8166",
          name: "Ability to forge per-form CSRF tokens given a global CSRF token",
          level: "MEDIUM",
          details: expected,
          help_url: "https://groups.google.com/forum/#!topic/rubyonrails-security/NOjKiGeXUgw",
          uri: "Gemfile.lock"
        )
      end
    end
  end

  describe 'sarif_report' do
    let(:scanner) { Salus::Scanners::BundleAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'ruby project with no vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/bundle_audit/no_cves') }
      it '' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        report_object = JSON.parse(report.to_sarif)['runs'][0]

        expect(report_object['invocations'][0]['executionSuccessful']).to eq(true)
      end
    end

    context 'ruby project with vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/bundle_audit/cves_found') }

      it 'should record failure and record the STDOUT from bundle-audit' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        result = JSON.parse(report.to_sarif)["runs"][0]["results"][0]
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"][0]

        expected = "It is possible to possible to, given a global CSRF token such as the"\
        " one\npresent in the authenticity_token meta tag, forge a per-form CSRF token for\nany"\
        " action for that session.\n\nVersions Affected:  rails < 5.2.5, rails < 6.0.4\nNot"\
        " affected:       Applications without existing HTML injection vulnerabilities.\nFixed"\
        " Versions:     rails >= 5.2.4.3, rails >= 6.0.3.1\n\nImpact\n------\n\nGiven the ability"\
        " to extract the global CSRF token, an attacker would be able to\nconstruct a per-form"\
        " CSRF token for that session.\n\nWorkarounds\n-----------\n\nThis is a low-severity"\
        " security issue. As such, no workaround is necessarily\nuntil such time as the"\
        " application can be upgraded.\n"

        # Check rule info
        expect(rules['id']).to eq('CVE-2020-8166')
        expect(rules['name']).to eq('Ability to forge per-form CSRF tokens given a global'\
          ' CSRF token')
        expect(rules['helpUri']).to eq("https://groups.google.com/forum/#!topic/rubyonrails"\
          "-security/NOjKiGeXUgw")
        expect(rules['fullDescription']['text']).to eq(expected)

        # Check result info
        expect(result['ruleId']).to eq('CVE-2020-8166')
        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq('error')
        expect(result['message']['text']).to eq(expected)
      end
    end
  end
end
