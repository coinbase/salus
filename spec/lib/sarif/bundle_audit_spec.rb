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
        expect(parsed_issue[:details]).to eq("Type: InsecureSource\nSource: http://rubygems.org/")

        issue = { "type": "UnpatchedGem",
        "url": '1' }
        parsed_issue = bundle_audit_sarif.parse_issue(issue)
        expect(parsed_issue[:id]).to eq("UnpatchedGem")

        issue = { "osvdb": "osvd value",
          "url": '3' }
        parsed_issue = bundle_audit_sarif.parse_issue(issue)
        expect(parsed_issue[:id]).to eq("osvd value")
      end

      it 'parses information correctly' do
        bundle_audit_sarif = Sarif::BundleAuditSarif.new(scanner.report)
        issue = scanner.report.to_h[:info][:vulnerabilities][0]

        # should Parse and fill out hash
        expected = "Package Name: actionpack\nType: UnpatchedGem\nVersion: 4.1.15\n Advisory"\
        " Title: Possible Strong Parameters Bypass in ActionPack\nDesciption: There is a strong"\
        " parameters bypass vector in ActionPack.\n\nVersions Affected:  rails <= 6.0.3\nNot "\
        "affected:       rails < 4.0.0\nFixed Versions:     rails >= 5.2.4.3, rails >= 6.0.3.1"\
        "\n\nImpact\n------\nIn some cases user supplied information can be inadvertently leaked"\
        " from\nStrong Parameters.  Specifically the return value of `each`, or `each_value`,\nor"\
        " `each_pair` will return the underlying \"untrusted\" hash of data that was\nread from "\
        "the parameters.  Applications that use this return value may be\ninadvertently use "\
        "untrusted user input.\n\nImpacted code will look something like this:\n\n```\ndef update"\
        "\n  # Attacker has included the parameter: `{ is_admin: true }`\n  "\
        "User.update(clean_up_params)\nend\n\ndef clean_up_params\n   params.each { |k, v|  "\
        "SomeModel.check(v) if k == :name }\nend\n```\n\nNote the mistaken use of `each` in the"\
        " `clean_up_params` method in the above\nexample.\n\nWorkarounds\n-----------\nDo not use"\
        " the return values of `each`, `each_value`, or `each_pair` in your\napplication.\n\n"\
        "Patched Versions: [\"~> 5.2.4.3\", \">= 6.0.3.1\"]\nUnaffected Versions: [\"< 4.0.0\"]\n"\
        "CVSS: \nOSVDB "

        expect(bundle_audit_sarif.parse_issue(issue)).to include(
          id: "CVE-2020-8164",
          details: expected,
          name: "Possible Strong Parameters Bypass in ActionPack",
          level: 0,
          help_url: "https://groups.google.com/forum/#!topic/rubyonrails-security/f6ioe4sdpbY",
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

      it 'should return valid sarif report' do
        report = Salus::Report.new(project_name: "Neon Genesis")
        report.add_scan_report(scanner.report, required: false)
        result = JSON.parse(report.to_sarif)["runs"][0]["results"][0]
        rules = JSON.parse(report.to_sarif)["runs"][0]["tool"]["driver"]["rules"][0]

        expected = "Package Name: actionpack\nType: UnpatchedGem\nVersion: 4.1.15\n Advisory"\
        " Title: Possible Strong Parameters Bypass in ActionPack\nDesciption: There is a strong"\
        " parameters bypass vector in ActionPack.\n\nVersions Affected:  rails <= 6.0.3\nNot "\
        "affected:       rails < 4.0.0\nFixed Versions:     rails >= 5.2.4.3, rails >= 6.0.3.1"\
        "\n\nImpact\n------\nIn some cases user supplied information can be inadvertently leaked"\
        " from\nStrong Parameters.  Specifically the return value of `each`, or `each_value`,\nor"\
        " `each_pair` will return the underlying \"untrusted\" hash of data that was\nread from "\
        "the parameters.  Applications that use this return value may be\ninadvertently use "\
        "untrusted user input.\n\nImpacted code will look something like this:\n\n```\ndef update"\
        "\n  # Attacker has included the parameter: `{ is_admin: true }`\n  "\
        "User.update(clean_up_params)\nend\n\ndef clean_up_params\n   params.each { |k, v|  "\
        "SomeModel.check(v) if k == :name }\nend\n```\n\nNote the mistaken use of `each` in the"\
        " `clean_up_params` method in the above\nexample.\n\nWorkarounds\n-----------\nDo not use"\
        " the return values of `each`, `each_value`, or `each_pair` in your\napplication.\n\n"\
        "Patched Versions: [\"~> 5.2.4.3\", \">= 6.0.3.1\"]\nUnaffected Versions: [\"< 4.0.0\"]\n"\
        "CVSS: \nOSVDB "

        # Check rule info
        expect(rules['id']).to eq('CVE-2020-8164')
        expect(rules['name']).to eq("Possible Strong Parameters Bypass in ActionPack")
        expect(rules['helpUri']).to eq("https://groups.google.com/forum/#!topic/rubyonrails"\
          "-security/f6ioe4sdpbY")
        expect(rules['fullDescription']['text']).to include(expected)

        # Check result info
        expect(result['ruleId']).to eq('CVE-2020-8164')
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
