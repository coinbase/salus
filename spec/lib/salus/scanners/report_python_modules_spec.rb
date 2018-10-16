require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportPythonModules do
  let(:blank_config) { {} }
  let(:report) { Salus::Report.new }
  let(:scan_report) { json_report['scans']['ReportPythonModules'] }
  let(:dependencies) { scan_report['info']['dependency'] }

  describe '#should_run?' do
    context 'no requirements file present' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        scanner = Salus::Scanners::ReportPythonModules.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(false)
      end
    end
  end
  describe '#run' do
    context 'basic requirements.txt' do
      it 'should report requirements' do
        repo = Salus::Repo.new('spec/fixtures/python/requirements_unpinned')
        scanner = Salus::Scanners::ReportPythonModules.new(
          repository: repo,
          report: report,
          config: blank_config
        )
        expect(scanner.should_run?).to eq(true)

        scanner.run
        expect(scan_report).not_to eq(nil), "ERROR: #{JSON.pretty_generate(json_report)}"

        deps = dependencies.map { |dep| [dep['name'], dep['version']] }
        expect(deps).to include(%w[requests >=2.5])
        expect(deps).to include(%w[six >=1.9])
        expect(deps).to include(%w[pycryptodome >=3.4.11])
      end
    end
  end
end
