require_relative '../../../spec_helper.rb'

describe Salus::Scanners::Base do
  let(:repository) { Salus::Repo.new('spec/fixtures/ruby_gem') }
  let(:scanner) { Salus::Scanners::Base.new(repository: repository, config: {}) }

  describe '#run' do
    it 'should raise an exception since this is an abstract function' do
      expect { scanner.run }.to raise_error(NoMethodError)
    end
  end

  describe '#should_run?' do
    it 'should raise an exception since this is an abstract function' do
      expect { scanner.should_run? }.to raise_error(NoMethodError)
    end
  end

  describe '#run_shell' do
    it 'should execute a shell command and yield a ShellResult with appropriate values' do
      fake_process_status = instance_double('Process::Status')
      allow(fake_process_status).to receive(:success?).and_return(false)
      allow(fake_process_status).to receive(:exitstatus).and_return(255)

      expect(Open3).to receive(:capture3).with({}, 'ls', stdin_data: '').and_return(
        [
          "file_a\nfile_b\nfile_c",
          'error string',
          fake_process_status
        ]
      )
      result = scanner.run_shell('ls')
      expect(result.stdout).to eq("file_a\nfile_b\nfile_c")
      expect(result.stderr).to eq('error string')
      expect(result.success?).to eq(false)
      expect(result.status).to eq(255)
    end
  end

  describe '#report_success' do
    it 'should log to the report that the scan passed' do
      expect { scanner.report_success }.to change { scanner.report.passed? }
        .from(false).to(true)
    end
  end

  describe '#report_failure' do
    it 'should log to the report that the scan failed' do
      expect { scanner.report_failure }.to change { scanner.report.failed? }
        .from(false).to(true)
    end
  end

  describe '#report_info' do
    it 'should store some info indexed by scanner and info type' do
      expect { scanner.report_info(:eva, 'AT Field active') }
        .to change { scanner.report.to_h.fetch(:info)[:eva] }
        .from(nil).to('AT Field active')
    end
  end

  describe '#report_stdout' do
    it 'should store the stdout of the scanner' do
      expect { scanner.report_stdout('Misato in command.') }
        .to change { scanner.report.to_h.fetch(:info)[:stdout] }
        .from(nil).to('Misato in command.')
    end
  end

  describe '#report_stderr' do
    it 'should store the stderr of the scanner' do
      expect { scanner.report_stderr('SCANNER FAILED') }
        .to change { scanner.report.to_h.fetch(:info)[:stderr] }
        .from(nil).to('SCANNER FAILED')
    end
  end
end
