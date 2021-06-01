require_relative '../../spec_helper.rb'

describe Sarif::BundleAuditSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::BundleAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'scan report with logged vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/bundle_audit/cves_found') }

      it 'updates ids accordingly' do
        bundle_audit_sarif = Sarif::BundleAuditSarif.new(scanner.report)
        issue = { "type": "InsecureSource",
          "source": "http://rubygems.org/" }

        parsed_issue = bundle_audit_sarif.parse_issue(issue)
        expect(parsed_issue[:id]).to eq("InsecureSource")
        expect(parsed_issue[:name]).to eq("InsecureSource http://rubygems.org/")
        expect(parsed_issue[:details]).to eq("Type: InsecureSource\nSource: http://rubygems.org/")

        issue = { "type": "UnpatchedGem",
                  "cve": "CVE1234",
                  "url": '1' }
        parsed_issue = bundle_audit_sarif.parse_issue(issue)
        expect(parsed_issue[:id]).to eq("CVE1234")

        issue = { "osvdb": "osvd value",
          "url": '3' }
        parsed_issue = bundle_audit_sarif.parse_issue(issue)
        expect(parsed_issue[:id]).to eq("osvd value")
      end

      it 'parses information correctly' do
        bundle_audit_sarif = Sarif::BundleAuditSarif.new(scanner.report)
        issue = scanner.report.to_h[:info][:vulnerabilities][0]

        expected_details = bundle_audit_sarif.parse_issue(issue)[:details]

        if expected_details.include?('CVE-2021-22885')
          details = 'Advisory Title: Possible Information Disclosure / Unintended Method Execution'
          expect(expected_details).to include(details)

          expect(bundle_audit_sarif.parse_issue(issue)).to include(
            id: "CVE-2021-22885",
            name: "Possible Information Disclosure / Unintended Method Execution in Action Pack",
            level: 0,
            help_url: "https://groups.google.com/g/rubyonrails-security/c/NiQl-48cXYI",
            uri: "Gemfile.lock"
          )
        else
          details = 'Advisory Title: Possible Strong Parameters Bypass in ActionPack'
          expect(expected_details).to include(details)

          expect(bundle_audit_sarif.parse_issue(issue)).to include(
            id: "CVE-2020-8164",
            name: "Possible Strong Parameters Bypass in ActionPack",
            level: 0,
            help_url: "https://groups.google.com/forum/#!topic/rubyonrails-security/f6ioe4sdpbY",
            uri: "Gemfile.lock"
          )
        end
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

      it 'should return valid sarif report' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        result = JSON.parse(report.to_sarif)["runs"][0]["results"][0]
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"][0]

        if rules['id'] == 'CVE-2021-22885'
          # Check rule info
          expect(rules['id']).to eq('CVE-2021-22885')
          rule_name = 'Possible Information Disclosure / Unintended Method Execution in Action Pack'
          expect(rules['name']).to eq(rule_name)
          rule_uri = 'https://groups.google.com/g/rubyonrails-security/c/NiQl-48cXYI'
          expect(rules['helpUri']).to eq(rule_uri)
          expected = 'Advisory Title: Possible Information Disclosure / Unintended'
          expect(rules['fullDescription']['text']).to include(expected)

          # Check result info
          expect(result['ruleId']).to eq('CVE-2021-22885')
        else
          # Check rule info
          expect(rules['id']).to eq('CVE-2020-8164')
          rule_name = 'Possible Strong Parameters Bypass in ActionPack'
          expect(rules['name']).to eq(rule_name)
          rule_uri = 'https://groups.google.com/forum/#!topic/rubyonrails-security/f6ioe4sdpbY'
          expect(rules['helpUri']).to eq(rule_uri)
          expected = 'Advisory Title: Possible Strong Parameters Bypass in ActionPack'
          expect(rules['fullDescription']['text']).to include(expected)

          # Check result info
          expect(result['ruleId']).to eq('CVE-2020-8164')
        end

        expect(result['ruleIndex']).to eq(0)
        expect(result['level']).to eq("note")
        expect(result['message']['text']).to include(expected)
      end
    end
  end

  describe '#sarif_level' do
    context 'Bundler audit severities' do
      it 'should be mapped to the right sarif level' do
        adapter = Sarif::BundleAuditSarif.new([])
        expect(adapter.sarif_level(0)).to eq("note")
        expect(adapter.sarif_level(5.6)).to eq("warning")
        expect(adapter.sarif_level(9.7)).to eq("error")
      end
    end
  end
end
