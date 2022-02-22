require_relative '../../../spec_helper.rb'

describe Salus::Scanners::Base do
  let(:repository) { Salus::Repo.new('spec/fixtures/ruby_gem') }
  let(:scanner) { Salus::Scanners::Base.new(repository: repository, config: {}) }

  describe 'run!' do
    let(:salus_report) { Salus::Report.new }
    let(:scanner) do
      Salus::Scanners::BundleAudit.new(
        repository: repository,
        config: { 'scanner_timeout_s' => 0 }
      )
    end
    before do
      allow(scanner).to receive(:run).and_raise(RuntimeError, 'bundle audit failed')
    end

    it 'should catch exceptions from scanners and record the error' do
      expect do
        scanner.run!(
          salus_report: salus_report,
          required: true,
          pass_on_raise: false,
          reraise: false
        )
      end.not_to raise_error

      salus_errors = salus_report.to_h[:errors]

      scanner_errors = salus_report.to_h[:scans]['BundleAudit'][:errors]
      expect(salus_errors).to eq(scanner_errors)
      expect(salus_errors.first).to include(
        message: 'Unhandled exception running BundleAudit: RuntimeError: bundle audit failed',
        error_class: RuntimeError
      )
    end

    it 'should catch exceptions and fail the build if pass_on_raise false' do
      expect do
        scanner.run!(
          salus_report: salus_report,
          required: true,
          pass_on_raise: false,
          reraise: false
        )
      end.not_to raise_error

      expect(salus_report.passed?).to eq(false)
    end

    it 'should catch exceptions and fail the build if pass_on_raise false' do
      expect do
        scanner.run!(
          salus_report: salus_report,
          required: true,
          pass_on_raise: true,
          reraise: false
        )
      end.not_to raise_error

      expect(salus_report.passed?).to eq(true)
    end

    it 'should time out when execution time exceeds configured timeout' do
      timeout_s = 2
      sleeping_scanner = Salus::Scanners::BundleAudit.new(
        repository: repository,
        config: { 'scanner_timeout_s' => timeout_s }
      )
      allow(sleeping_scanner).to receive(:run) { sleep(5) }
      expect do
        sleeping_scanner.run!(
          salus_report: salus_report,
          required: true,
          pass_on_raise: false,
          reraise: true
        )
      end.to raise_error(
        Salus::Scanners::Base::ScannerTimeoutError,
        "Scanner BundleAudit timed out after #{timeout_s} seconds"
      )
    end
  end

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
      chdir = File.expand_path(repository.path_to_repo)
      expect(Open3).to receive(:capture3).with({}, 'ls', stdin_data: '', chdir: chdir).and_return(
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

  describe '#build_options' do
    let(:scanner) do
      Salus::Scanners::Base.new(repository: repository, config: {
                                  'flag' => 'true',
                                  'onlyLow' => 'low',
                                  'bool' => 'true',
                                  'file' => './bla.js',
                                  'list' => %w[foo bar 1 2],
                                  'multiple' => %w[first second third],
                                  'onlyHigh' => 'foobarbaz', # Invalid
                                  'notUsed' => 'neverShouldBeThere',
                                  'longName' => 'true' # should rename to shortname
                                })
    end

    it 'should build the options correctly based on a hash' do
      # Note, this doesn't test that it checks for files properly since when running rspec
      options = scanner.build_options(
        prefix: '-',
        suffix: ' ',
        separator: '=',
        args: {
          flag: :flag,
          onlyLow: /^low$/i, # Automatically knows it is a string
          bool: 'bool', # Test if you use a string for the type
          file: {
            type: :string,
            prefix: '--', # test for custom prefix
            separator: '&', # Test for custom separator
            suffix: '%%% ' # Test for custom end
          },
          list: :list, # use defaults
          notThere: :string, # Not in the config
          onlyHigh: /^high$/i, # not allowed, return empty string
          multiple: :string,
          longName: {
            keyword: 'shortName',
            type: :flag
          }
        }
      )
      expect(options).to start_with('-flag ') # Respects order
      expect(options).to include(' -bool=true')
      expect(options).to include(' -onlyLow=low')
      expect(options).to include(' --file&./bla.js%%% ')
      expect(options).to include(' -list=foo,bar,1,2 ')
      expect(options).to include(' -multiple=first ')
      expect(options).to include(' -multiple=second ')
      expect(options).to include(' -multiple=third ')
      expect(options).to include(' -shortName ')
      expect(options).not_to include('notThere')
      expect(options).not_to include('high') # No 'high' anywhere in options
      expect(options).not_to include('neverShouldBeThere') # No 'high' anywhere in options
      expect(options).not_to include('foobarbaz') # No 'foobarbaz' anywhere in options
      expect(options).not_to include('longName') # No 'longName' anywhere in options
    end
  end
end
