require_relative '../../../spec_helper.rb'

describe Salus::Scanners::Gosec do
  describe '#run' do
    let(:scanner) { Salus::Scanners::Gosec.new(repository: repo, config: {}) }

    before { scanner.run }

    context 'non-go project' do
      let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }

      it 'should record the STDERR of gosec' do
        expect(scanner.should_run?).to eq(false)
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        errors = scanner.report.to_h.fetch(:errors).first
        expect(
          info[:stderr]
        ).to include(
          'No packages found' # debug information
        )
        expect(
          errors[:message]
        ).to include('0 lines of code were scanned')
      end
    end

    context 'go project with vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/vulnerable_goapp') }

      it 'should record failure and record the STDOUT from gosec' do
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).to include('Potential hardcoded credentials')
      end
    end

    context 'go project with vulnerabilities in a nested folder' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/recursive_vulnerable_goapp') }

      it 'should record failure and record the STDOUT from gosec' do
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).to include('Potential hardcoded credentials')
      end
    end

    context 'go project with no known vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/safe_goapp') }

      it 'should report a passing scan' do
        expect(scanner.report.passed?).to eq(true)
      end
    end

    context 'go project with malformed go' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/malformed_goapp') }

      it 'should report a failing scan' do
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)

        expect(info[:stdout]).to include('Golang errors', 'Pintl not declared by package fmt')
        expect(logs).to include('Golang errors', 'Pintl not declared by package fmt')
      end
    end
  end

  describe '#run from multiple subdirs' do
    context 'go project with multiple sub-projects' do
      let(:repo) { 'spec/fixtures/gosec/multi_goapps' }

      it 'should report failures in both sub-projects' do
        # test case shows gosec only runs from the specified subdirs in salus.yaml
        # there are 3 identical subdirs in the repo: app1, app2, app3, all with vulns
        # salus.yaml says run_from_dirs = [app1, app2]
        # so result vulns are reported for app1 and app2 only, not app3
        config_file = "#{repo}/salus.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Gosec']
        scanner = Salus::Scanners::Gosec.new(repository: Salus::Repo.new(repo), config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        issues_arr = logs['Issues']
        golang_errs = logs['Golang errors']

        expect(issues_arr.size).to eq(6)
        expect(issues_arr.to_s).to include('/multi_goapps/app1/hello.go')
        expect(issues_arr.to_s).to include('/multi_goapps/app2/hello.go')
        expect(golang_errs.size).to eq(2)
        expect(golang_errs.to_s).to include('/multi_goapps/app1/hello.go')
        expect(golang_errs.to_s).to include('/multi_goapps/app2/hello.go')
      end
    end
  end

  describe '#should_run?' do
    let(:scanner) { Salus::Scanners::Gosec.new(repository: repo, config: {}) }

    shared_examples_for "when go file types are present" do
      it 'returns true' do
        expect(scanner.should_run?).to eq(true)
      end
    end

    it_behaves_like "when go file types are present" do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/safe_goapp') }
    end

    it_behaves_like "when go file types are present" do
      let(:repo) { Salus::Repo.new('spec/fixtures/report_go_dep') }
    end

    it_behaves_like "when go file types are present" do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/mod_goapp') }
    end

    it_behaves_like "when go file types are present" do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/sum_goapp') }
    end

    context 'when go file types are missing' do
      let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }

      it 'returns false' do
        expect(scanner.should_run?).to eq(false)
      end
    end
  end

  describe '#config_options' do
    let(:scanner) { Salus::Scanners::Gosec.new(repository: repo, config: {}) }
    let(:config_scanner) { Salus::Scanners::Gosec.new(repository: repo, config: config) }

    before(:example) do
      scanner.run
      config_scanner.run
    end

    context 'when using nosec' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/nosec') }

      context 'and nosec is set to true' do
        let(:config) { { "nosec" => "true" } }

        it 'disables nosec comments' do
          expect(scanner.report.passed?).to eq(true)
          expect(config_scanner.report.passed?).to eq(false)
        end
      end

      context 'and nosec is set to false' do
        let(:config) { { "nosec" => "false" } }

        it 'enables nosec comments' do
          expect(scanner.report.passed?).to eq(true)
          expect(config_scanner.report.passed?).to eq(true)
        end
      end

      context 'and nosec is not set to a boolean' do
        let(:config) { { "nosec" => "blah" } }

        it 'warns when not provided a valid options' do
          expect(config_scanner.report.to_h.fetch(:warn)).to include(:scanner_misconfiguration)
        end
      end
    end

    context 'when using nosec-tag' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/nosec-tag') }

      context 'and a valid tag' do
        let(:config) { { "nosec-tag" => "falsepositive" } }

        it 'respects nosec-tag over nosec' do
          expect(scanner.report.passed?).to eq(false)
          expect(config_scanner.report.passed?).to eq(true)
        end

        context 'and disabling nosec' do
          let(:config) { { "nosec-tag" => "falsepositive", "nosec" => "true" } }

          it 'respects nosec settings also' do
            expect(scanner.report.passed?).to eq(false)
            expect(config_scanner.report.passed?).to eq(false)
          end
        end
      end

      context 'and an invalid tag' do
        let(:config) { { "nosec-tag" => "" } }
        it 'warns when not provided a valid option' do
          expect(config_scanner.report.to_h.fetch(:warn)).to include(:scanner_misconfiguration)
        end
      end
    end

    context 'when using a conf file' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/gosecconfig_goapp') }
      let(:config) { { "conf" => "config.json" } }

      #      it 'disables nosec comments' do
      #        expect(scanner.report.passed?).to eq(true)
      #        expect(config_scanner.report.passed?).to eq(false)
      #      end
    end

    context 'when including rules' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/vulnerable_goapp') }
      let(:config) { { "include" => ["G101"] } }

      it 'actually includes only the given rules' do
        expect(config_scanner.report.passed?).to eq(false)
      end

      context 'and when using nosec flag' do
        let(:repo) { Salus::Repo.new('spec/fixtures/gosec/gosec_rules') }
        let(:config) { { "include" => ["G101"], "nosec" => "true" } }

        it 'only scans for included rules even if issue is whitelisted' do
          expect(config_scanner.report.passed?).to eq(false)
        end
      end
    end

    context 'when excluding rules' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/gosec_rules') }
      let(:config) { { "exclude" => ["G101"] } }

      it 'actually excludes only the given rules' do
        expect(config_scanner.report.passed?).to eq(true)
      end

      context 'and when using nosec flag' do
        let(:repo) { Salus::Repo.new('spec/fixtures/gosec/gosec_rules') }
        let(:config) { { "exclude" => ["G101"], "nosec" => "true" } }

        it 'only scans for included rules even if issue is whitelisted' do
          expect(config_scanner.report.passed?).to eq(true)
        end
      end
    end

    context 'active exceptions' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/gosec_rules') }
      let(:exceptions) do
        [{ 'advisory_id' => "G101",
          'expiration' => '2022-12-31',
          'changed_by' => 'appsec',
          'notes' => 'foo' }]
      end
      let(:config) { { "exceptions" => exceptions, "nosec" => "true" } }

      before(:each) do
        allow(Date).to receive(:today).and_return Date.new(2021, 12, 31)
      end

      it 'should honor active exceptions' do
        expect(config_scanner.report.passed?).to eq(true)
      end
    end

    context 'expired exceptions' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/gosec_rules') }
      let(:exceptions) do
        [{ 'advisory_id' => "G101",
          'expiration' => '2020-12-31',
          'changed_by' => 'appsec',
          'notes' => 'foo' }]
      end
      let(:config) { { "exceptions" => exceptions, "nosec" => "true" } }

      before(:each) do
        allow(Date).to receive(:today).and_return Date.new(2021, 12, 31)
      end

      it 'should ignore expired exceptions' do
        expect(config_scanner.report.passed?).to eq(false)
      end
    end

    context 'when sorting by severity' do
      require 'json'
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/multiple_vulns') }
      let(:config) { { "sort" => "true" } }

      it 'is sorted in the report' do
        gosec_report = JSON.parse(config_scanner.report.to_h[:logs])
        issues_arr = gosec_report["Issues"]

        map = { "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3 }

        issues_arr.each_cons(2) do |first, second|
          expect(map[first["severity"]]).to be <= map[second["severity"]]
        end
      end
    end

    # context 'when using build tags' do
    #  let(:repo) { Salus::Repo.new('spec/fixtures/gosec/vulnerable_goapp') }
    #  let(:config) { { "tags" => "prod" } }

    # TODO
    # end

    context 'when filtering by severity' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/multiple_vulns') }
      let(:config) { { "severity" => "high" } }

      it 'is filtered by severity' do
        gosec_report = JSON.parse(config_scanner.report.to_h[:logs])
        issues_arr = gosec_report["Issues"]

        issues_arr.each do |issue|
          expect(issue["severity"]).to eq("HIGH")
        end
      end
    end

    context 'when filtering by confidence' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/multiple_vulns') }
      let(:config) { { "confidence" => "high" } }

      it 'filtered by confidence' do
        gosec_report = JSON.parse(config_scanner.report.to_h[:logs])
        issues_arr = gosec_report["Issues"]

        issues_arr.each do |issue|
          expect(issue["confidence"]).to eq("HIGH")
        end
      end
    end

    context 'when the scan should be forced to pass' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/multiple_vulns') }
      let(:config) { { "no-fail" => "true" } }

      it 'always passes' do
        expect(scanner.report.passed?).to eq(false)
        expect(config_scanner.report.passed?).to eq(true)
      end
    end

    context 'when scanning tests' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/tests_goapp') }
      let(:config) { { "tests" => "true" } }

      it 'scans for issues in test files' do
        expect(scanner.report.passed?).to eq(true)
        expect(config_scanner.report.passed?).to eq(false)
      end
    end

    context 'when excluding directories' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/multifolder_goapp') }

      context 'and is a real directory' do
        let(:config) { { "exclude-dir" => ["src/more_src"] } }

        it 'ignores directories' do
          expect(scanner.report.passed?).to eq(false)
          expect(config_scanner.report.passed?).to eq(true)
        end
      end

      context 'and is not a real directory' do
        let(:config) { { "exclude-dir" => ["src2"] } }

        it 'issues a warning' do
          expect(config_scanner.report.to_h.fetch(:warn)).to include(:scanner_misconfiguration)
        end
      end
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/gosec')
        scanner = Salus::Scanners::Gosec.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return go' do
        langs = Salus::Scanners::Gosec.supported_languages
        expect(langs).to eq(['go'])
      end
    end
  end
end
