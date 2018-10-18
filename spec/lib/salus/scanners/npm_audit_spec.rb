require_relative '../../../spec_helper.rb'

describe Salus::Scanners::NPMAudit do
  describe '#run' do
    let(:report) { Salus::Report.new }
    let(:scan_report) { json_report['scans']['NPMAudit'] }
    let(:scan_errors) { json_report['errors']['NPMAudit'] }

    # Make sure we get consistent timestamps to compare against
    # the output fixtures
    before(:each) do
      allow(Process)
        .to receive(:clock_gettime)
        .with(Process::CLOCK_MONOTONIC).and_return(0.0)
    end

    cases = [
      [
        'when all advisories apply only to dev deps',
        'success_dev_advisories',
        true
      ],
      [
        'when there are exceptions for all advisories',
        'success_excepted_advisories',
        true
      ],
      [
        'when there are exceptions for all advisories (and there is a lockfile)',
        'success_excepted_advisories_with_lockfile',
        true
      ],
      [
        'when there are extraneous exceptions for dev advisories',
        'success_extraneous_dev_exceptions',
        true
      ],
      [
        'when there are extraneous exceptions',
        'success_extraneous_exceptions',
        true
      ],
      [
        'when there are no advisories',
        'success_no_advisories',
        true
      ],
      [
        'when there are advisories and no exceptions',
        'failure_no_exceptions',
        false
      ],
      [
        'when there are advisories and no exceptions (and there is a lockfile)',
        'failure_no_exceptions_with_lockfile',
        false
      ],
      [
        'when there are exceptions, but not all advisories are covered',
        'failure_missing_exceptions',
        false
      ],
      [
        'when an error condition causes npm audit to fail in an unusual way',
        'failure_bad_lockfile',
        false
      ]
    ].freeze

    cases.each do |description, fixture, success|
      path_to_repo = "spec/fixtures/npm_audit/#{fixture}"

      config =
        if File.exist?("#{path_to_repo}/salus.yaml")
          YAML.load_file("#{path_to_repo}/salus.yaml")['scanner_configs']['NPMAudit']
        else
          {}
        end

      lockfile_existed = File.exist?("#{path_to_repo}/package-lock.json")
      expected_output = File.read("#{path_to_repo}/expected_output.txt")

      it "reports #{success ? 'success' : 'failure'} #{description}" do
        Salus::Scanners::NPMAudit.new(
          repository: Salus::Repo.new(path_to_repo),
          report: report,
          config: config
        ).run

        expect(scan_report['passed']).to eq(success)
        expect(File.exist?("#{path_to_repo}/package-lock.json")).to eq(lockfile_existed)
        expect(scan_report['stdout']).to eq(expected_output)
      end
    end
  end

  describe '#should_run?' do
    context 'no relevant files present' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.package_json_present?).to eq(false)
        scanner = Salus::Scanners::NPMAudit.new(repository: repo, report: nil, config: {})
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'package.json is present' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/npm_audit/success_no_advisories')
        expect(repo.package_json_present?).to eq(true)
        scanner = Salus::Scanners::NPMAudit.new(repository: repo, report: nil, config: {})
        expect(scanner.should_run?).to eq(true)
      end
    end
  end
end
