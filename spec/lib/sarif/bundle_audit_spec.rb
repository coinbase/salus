require_relative '../../spec_helper.rb'

describe Sarif::BundleAuditSarif do
  describe '#parse_issue' do
    let(:scanner) { Salus::Scanners::BundleAudit.new(repository: repo, config: {}) }
    before { scanner.run }

    context 'scan report with logged vulnerabilities' do
      let(:path) { 'spec/fixtures/bundle_audit/cves_found' }
      let(:repo) { Salus::Repo.new(path) }

      it 'updates ids accordingly' do
        bundle_audit_sarif = Sarif::BundleAuditSarif.new(scanner.report, path)
        issue = { "type": "InsecureSource",
                  "source": "http://rubygems.org/",
                  "line_number": 123 }

        parsed_issue = bundle_audit_sarif.parse_issue(issue)
        expect(parsed_issue[:id]).to eq("InsecureSource")
        expect(parsed_issue[:name]).to eq("InsecureSource http://rubygems.org/")
        expect(parsed_issue[:details]).to eq("Type: InsecureSource\nSource: http://rubygems.org/")
        expect(parsed_issue[:start_line]).to eq(123)
        expect(parsed_issue[:start_column]).to eq(1)

        issue = { "type": "UnpatchedGem",
                  "cve": "CVE1234",
                  "url": '1',
                  "line_number": 456,
                  "name": "boo" }
        parsed_issue = bundle_audit_sarif.parse_issue(issue)
        expect(parsed_issue[:id]).to eq("CVE1234")
        expect(parsed_issue[:start_line]).to eq(456)
        expect(parsed_issue[:start_column]).to eq(1)
        expect(parsed_issue[:code]).to eq('boo')

        issue = { "osvdb": "osvd value",
          "url": '3', "line_number": 789 }
        parsed_issue = bundle_audit_sarif.parse_issue(issue)
        expect(parsed_issue[:id]).to eq("osvd value")
        expect(parsed_issue[:start_line]).to eq(789)
        expect(parsed_issue[:start_column]).to eq(1)
      end

      it 'parses information correctly' do
        bundle_audit_sarif = Sarif::BundleAuditSarif.new(scanner.report, path)
        issue = scanner.report.to_h[:info][:vulnerabilities]
        issue = issue.detect { |i| i[:cve] == 'CVE-2021-22885' }

        expected_details = bundle_audit_sarif.parse_issue(issue)[:details]

        if expected_details.include?('CVE-2021-22885')
          details = 'There is a possible information disclosure / unintended method'
          expect(expected_details).to include(details)

          expect(bundle_audit_sarif.parse_issue(issue)).to include(
            id: "CVE-2021-22885",
            name: "Possible Information Disclosure / Unintended Method Execution in Action Pack",
            level: 0,
            help_url: "https://groups.google.com/g/rubyonrails-security/c/NiQl-48cXYI",
            uri: "Gemfile.lock",
            start_line: 8,
            start_column: 1,
            code: 'actionpack'
          )
        else
          details = 'There is a possible DoS vulnerability in the Token Authentication logic in'
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
        cve = 'CVE-2021-22885'

        sarif = JSON.parse(report.to_sarif({ 'include_non_enforced' => true }))
        results = sarif["runs"][0]["results"]
        result = results.detect { |r| r["ruleId"] == cve }

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule = rules.detect { |r| r["id"] == cve }

        # Check rule info
        expect(rule['id']).to eq(cve)
        rule_name = 'Possible Information Disclosure / Unintended Method Execution in Action Pack'
        expect(rule['name']).to eq(rule_name)
        rule_uri = 'https://groups.google.com/g/rubyonrails-security/c/NiQl-48cXYI'
        expect(rule['helpUri']).to eq(rule_uri)
        expected = 'There is a possible information disclosure / unintended method'
        expect(rule['fullDescription']['text']).to include(expected)

        # Check result info
        expect(result['ruleId']).to eq(cve)
        expect(result['level']).to eq("note")
        expect(result['message']['text']).to include(expected)
        region = result['locations'][0]['physicalLocation']['region']
        expect(region['startLine']).to eq(8)
        expect(region['startColumn']).to eq(1)
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

  describe 'sarif diff' do
    context 'git diff support' do
      let(:new_lines_in_git_diff) do
        git_diff_file = 'spec/fixtures/sarifs/diff/git_diff_7.txt'
        git_diff = File.read(git_diff_file)
        Sarif::BaseSarif.new_lines_in_git_diff(git_diff)
      end

      it 'should find code in git diff' do
        snippet = 'helloworld'
        r = Sarif::BundleAuditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true
        snippet = 'bye'
        r = Sarif::BundleAuditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be true
      end

      it 'should not match part of the package name' do
        snippet = 'hello'
        r = Sarif::BundleAuditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be false
      end

      it 'should not match package that was in git diff but not added with this commit' do
        snippet = 'fuubar'
        r = Sarif::BundleAuditSarif.snippet_possibly_in_git_diff?(snippet, new_lines_in_git_diff)
        expect(r).to be false
      end
    end
  end
end
