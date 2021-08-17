require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportGoDep do
  describe '#run' do
    it 'should throw an error if no go.mod, go.sum, or Gopkg.lock is present' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})

      expect { scanner.run }.to raise_error(
        Salus::Scanners::Base::InvalidScannerInvocationError,
        'Cannot report on Go dependencies without a Gopkg.lock, go.mod, or go.sum file'
      )
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
            version_tag: nil
          },
          {
            dependency_file: 'Gopkg.lock',
            type: 'golang',
            name: 'github.com/Sirupsen/logrus',
            reference: 'ba1b36c82c5e05c4f912a88eab0dcd91a171688f',
            version_tag: 'v0.11.5'
          },
          {
            dependency_file: 'Gopkg.lock',
            type: 'golang',
            name: 'golang.org/x/sys',
            reference: '9a7256cb28ed514b4e1e5f68959914c4c28a92e0',
            version_tag: nil
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
            name: 'github.cbhq.net/c3/bls12-381',
            reference: 'N/A for go.mod/go.sum dependencies',
            version_tag: "v0.0.0-20210114210818-577bfdc5cb9c"
          },
          {
            dependency_file: 'go.sum',
            type: 'golang',
            name: 'github.cbhq.net/c3/bls12-381',
            reference: 'N/A for go.mod/go.sum dependencies',
            version_tag: "v0.0.0-20210114210818-577bfdc5cb9c/go.mod"
          },
          {
            dependency_file: 'go.sum',
            type: 'golang',
            name: 'github.com/davecgh/go-spew',
            reference: 'N/A for go.mod/go.sum dependencies',
            version_tag: "v1.1.0"
          }
        ]
      )
    end
  end

  describe '#record_dep_from_go_mod' do
    it 'should send an event and report warning' do
      Salus::PluginManager.register_listener(listener)

      repo = Salus::Repo.new('spec/fixtures/report_go_mod')
      scanner = Salus::Scanners::ReportGoDep.new(repository: repo, config: {})

      scanner.run
      warnings = scanner.report.to_h.fetch(:warn)

      expect(listener).to receive(:report_go_dep_scan).with(
        'This repository contains no go.sum or Gopkg.lock file. Currently '\
        'go.mod files are unsupported for reporting Golang dependencies'
      )

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
