require_relative '../../../spec_helper.rb'

describe Salus::Scanners::RepoNotEmpty do
  let(:blank_config)  { {} }
  let(:report)        { Salus::Report.new }
  let(:scan_report)   { json_report['scans']['RepoNotEmpty'] }

  describe '#run' do
    context 'non blank directory' do
      it 'should be a simple pass' do
        scanner = Salus::Scanners::RepoNotEmpty.new(
          repository: Salus::Repo.new('spec/fixtures/repo_not_empty/non_blank'),
          report: report,
          config: blank_config
        )
        scanner.run
        expect(scan_report['passed']).to eq(true)
      end
    end

    context 'blank directory' do
      let(:blank_dir) { 'spec/fixtures/repo_not_empty/blank' }

      it 'should be a simple pass' do
        Dir.mktmpdir(blank_dir) do
          expect(Dir["#{blank_dir}/*"]).to be_empty

          scanner = Salus::Scanners::RepoNotEmpty.new(
            repository: Salus::Repo.new(blank_dir),
            report: report,
            config: blank_config
          )
          scanner.run

          expect(scan_report['passed']).to eq(false)
          expect(scan_report['info']['problem']).to include(/may indicate misconfiguration/)
        end
      end
    end
  end
end
