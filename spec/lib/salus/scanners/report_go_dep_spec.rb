require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportGoDep do
  describe '#run' do
    it 'should return nothing if no go.mod, go.sum, or Gopkg.lock is present' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})

      expect(scanner.run).to eq(nil)
    end

    it 'should report on all the dependencies in the Gopkg.lock file' do
      repo = Salus::Repo.new('spec/fixtures/report_go_dep')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})

      scanner.run

      dependencies = scanner.report.to_h.fetch(:info).fetch(:dependencies)

      expect(dependencies).to match_array(
        [
          {
            dependency_file: 'Gopkg.lock',
            type: 'golang',
            name: 'github.com/PagerDuty/go-pagerduty',
            reference: 'fe74e407c23e030fa1523e7cbd972398fd85ec5d',
            version: '',
            namespace: '',
            checksum: ''
          },
          {
            dependency_file: 'Gopkg.lock',
            type: 'golang',
            name: 'github.com/Sirupsen/logrus',
            reference: 'ba1b36c82c5e05c4f912a88eab0dcd91a171688f',
            version: '0.11.5',
            namespace: '',
            checksum: ''
          },
          {
            dependency_file: 'Gopkg.lock',
            type: 'golang',
            name: 'golang.org/x/sys',
            reference: '9a7256cb28ed514b4e1e5f68959914c4c28a92e0',
            version: '',
            namespace: '',
            checksum: ''
          }
        ]
      )
    end
  end

  describe '#record_dep_from_go_sum' do
    it 'should report on all the dependencies in the go.sum file' do
      repo = Salus::Repo.new('spec/fixtures/report_go_sum')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})

      scanner.run

      dependencies = scanner.report.to_h.fetch(:info).fetch(:dependencies)

      expect(dependencies[0..2]).to match_array(
        [
          {
            dependency_file: 'go.sum',
            type: 'golang',
            namespace: 'github.cbhq.net/c3',
            name: 'github.cbhq.net/c3/bls12-381',
            reference: 'N/A for go.mod/go.sum dependencies',
            checksum: 'H6qPVjeq1XbGuaFaFD9aIXh7ZBmFziVAQCNRhBw8XnU=',
            version: "0.0.0-20210114210818-577bfdc5cb9c"
          },
          {
            dependency_file: 'go.sum',
            type: 'golang',
            namespace: 'github.cbhq.net/c3',
            name: 'github.cbhq.net/c3/bls12-381',
            reference: 'N/A for go.mod/go.sum dependencies',
            checksum: 'GKWeplG/c6sSm2WEWBVzld/RnaaMxB/4U0hk5lbKWqc=',
            version: "0.0.0-20210114210818-577bfdc5cb9c"
          },
          {
            dependency_file: 'go.sum',
            type: 'golang',
            namespace: 'github.com/davecgh',
            name: 'github.com/davecgh/go-spew',
            reference: 'N/A for go.mod/go.sum dependencies',
            checksum: 'ZDRjVQ15GmhC3fiQ8ni8+OwkZQO4DARzQgrnXU1Liz8=',
            version: "1.1.0"
          }
        ]
      )
    end
  end

  describe '#record_dep_from_go_mod' do
    let(:listener) { Object.new }
    before(:each) do
      def listener.report_warn(data)
        data
      end
    end

    it 'should send an event and report warning' do
      Salus::PluginManager.register_listener(listener)

      repo = Salus::Repo.new('spec/fixtures/report_go_mod')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})

      expect(listener).to receive(:report_warn).with(
        {
          type: :report_go_dep_missing_go_sum,
          message: 'WARNING: No go.sum/Gopkg.lock found. Currently '\
          'go.mod is unsupported for reporting Golang dependencies.'
        }
      )

      scanner.run
      warnings = scanner.report.to_h.fetch(:warn)

      expect(warnings[:report_go_dep_missing_go_sum]).to eq(
        'WARNING: No go.sum/Gopkg.lock found. Currently go.mod is '\
        'unsupported for reporting Golang dependencies.'
      )
    end
  end

  describe '#should_run?' do
    it 'should return false if Gopkg.lock is absent' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      expect(repo.dep_lock_present?).to eq(false)
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if Gopkg.lock is present' do
      repo = Salus::Repo.new('spec/fixtures/report_go_dep')
      expect(repo.dep_lock_present?).to eq(true)
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})
        expect(scanner.version).to eq('')
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::ReportGoDep.supported_languages
        expect(langs).to eq(['go'])
      end
    end
  end
end
