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
          'no buildable Go source files in /go/src/repo/spec/fixtures/blank_repository'
        )
        expect(
          errors[:message]
        ).to include('gosec exited with build error')
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

    context 'go project with no known vulnerabilities' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gosec/safe_goapp') }

      it 'should report a passing scan' do
        expect(scanner.report.passed?).to eq(true)
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
end
