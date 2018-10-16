require_relative '../spec_helper.rb'

describe Salus::CLI do
  # prevent actual system exits because they kill tests
  before do
    allow(Salus).to receive(:system_exit) do |arg|
      arg # just return the input
    end
  end

  describe '#scan' do
    context 'without configuration arguments or envars' do
      it 'runs without error' do
        # there is a Salus::Processor::DEFAULT_PATH folder here for testing
        Dir.chdir('spec/fixtures/salus/success') do
          expect(Salus.scan).to eq(Salus::EXIT_SUCCESS)
        end
      end
    end

    context 'with default configuration of local salus.yaml file' do
      it 'runs and exits failure since the overall scan failed' do
        Dir.chdir('spec/fixtures/salus/failure') do
          # This should hit the local config file which enforces a failing pattern search.
          expect(Salus.scan).to eq(Salus::EXIT_FAILURE)
        end
      end
    end

    context 'with configuration argument' do
      it 'runs and exits failure since the overall scan failed' do
        Dir.chdir('spec/fixtures/salus/success') do
          expect(
            Salus.scan(config: 'file:///failure_salus.yaml')
          ).to eq(Salus::EXIT_FAILURE)
        end
      end
    end

    context 'with configuration envars' do
      it 'runs and exits failure since the overall scan failer' do
        Dir.chdir('spec/fixtures/salus/success') do
          ENV['SALUS_CONFIGURATION'] = 'file:///failure_salus.yaml'
          expect(Salus.scan).to eq(Salus::EXIT_FAILURE)
        end
      end
    end

    context 'with configuration envars' do
      it 'runs and exits failure since the overall scan failer' do
        Dir.chdir('spec/fixtures/salus/success') do
          expect { Salus.scan(quiet: false) }.to output.to_stdout
          expect { Salus.scan(quiet: true) }.not_to output.to_stdout
        end
      end
    end

    context 'with configuration envars' do
      it 'runs and exits failure since the overall scan failed' do
        Dir.chdir('spec/fixtures/salus/verbose') do
          # This is in the info column of ReportRubyGems scanner row.
          info_regex = /INFO - dependency/

          ENV['SALUS_CONFIGURATION'] = 'file:///salus.yaml'

          # Check default which is verbose: false.
          expect { Salus.scan }.not_to output(info_regex).to_stdout

          # Check that verbose: true gives use info output.
          expect { Salus.scan(verbose: true) }.to output(info_regex).to_stdout
        end
      end
    end
  end
end
