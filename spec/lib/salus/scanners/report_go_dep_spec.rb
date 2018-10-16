require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportGoDep do
  let(:blank_config) { {} }
  let(:report) { Salus::Report.new }
  let(:scan_report) { json_report['scans']['ReportGoDep'] }

  describe '#run' do
    context 'no Gopkg.lock present' do
      it 'should throw an error since there is nothing to parse' do
        scanner = Salus::Scanners::ReportGoDep.new(
          repository: Salus::Repo.new('spec/fixtures/blank_repository'),
          report: report,
          config: blank_config
        )
        expect { scanner.run }.to raise_error(
          NotImplementedError,
          'Cannot report on Go dependencies without a Gopkg.lock file.'
        )
      end
    end

    context 'Gopkg.lock present' do
      it 'should report on all the dependencies in the Gopkg.lock file' do
        scanner = Salus::Scanners::ReportGoDep.new(
          repository: Salus::Repo.new('spec/fixtures/report_go_dep'),
          report: report,
          config: blank_config
        )
        scanner.run
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gopkg.lock',
          'type' => 'go_dep_lock',
          'name' => 'github.com/PagerDuty/go-pagerduty',
          'reference' => 'fe74e407c23e030fa1523e7cbd972398fd85ec5d',
          'version_tag' => nil
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gopkg.lock',
          'type' => 'go_dep_lock',
          'name' => 'github.com/Sirupsen/logrus',
          'reference' => 'ba1b36c82c5e05c4f912a88eab0dcd91a171688f',
          'version_tag' => 'v0.11.5'
        )
        expect(scan_report['info']['dependency']).to include(
          'dependency_file' => 'Gopkg.lock',
          'type' => 'go_dep_lock',
          'name' => 'golang.org/x/sys',
          'reference' => '9a7256cb28ed514b4e1e5f68959914c4c28a92e0',
          'version_tag' => nil
        )
      end
    end
  end

  describe '#should_run?' do
    context 'no Gopkg.lock present' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.dep_lock_present?).to eq(false)
        scanner = Salus::Scanners::ReportGoDep.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'Gopkg.lock is present' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/report_go_dep')
        expect(repo.dep_lock_present?).to eq(true)
        scanner = Salus::Scanners::ReportGoDep.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(true)
      end
    end
  end
end
