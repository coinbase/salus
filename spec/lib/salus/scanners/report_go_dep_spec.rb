require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportGoDep do
  describe '#run' do
    it 'should throw an error if no Gopkg.lock is present' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})

      expect { scanner.run }.to raise_error(
        Salus::Scanners::Base::InvalidScannerInvocationError,
        'Cannot report on Go dependencies without a Gopkg.lock file.'
      )
    end

    it 'should report on all the dependencies in the Gopkg.lock file' do
      repo = Salus::Repo.new('spec/fixtures/report_go_dep')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})

      scanner.run

      dependencies = scanner.report.to_h.fetch(:info).fetch(:dependencies)

      expect(dependencies).to match_array([
                                            {
                                              dependency_file: 'Gopkg.lock',
                                              type: 'go_dep_lock',
                                              name: 'github.com/PagerDuty/go-pagerduty',
                                              reference: 'fe74e407c23e030fa1523e7cbd972398fd85ec5d',
                                              version_tag: nil
                                            },
                                            {
                                              dependency_file: 'Gopkg.lock',
                                              type: 'go_dep_lock',
                                              name: 'github.com/Sirupsen/logrus',
                                              reference: 'ba1b36c82c5e05c4f912a88eab0dcd91a171688f',
                                              version_tag: 'v0.11.5'
                                            },
                                            {
                                              dependency_file: 'Gopkg.lock',
                                              type: 'go_dep_lock',
                                              name: 'golang.org/x/sys',
                                              reference: '9a7256cb28ed514b4e1e5f68959914c4c28a92e0',
                                              version_tag: nil
                                            }
                                          ])
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
end
