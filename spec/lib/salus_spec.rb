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
          expect(Salus.scan(quiet: true)).to eq(Salus::EXIT_SUCCESS)
        end
      end
    end

    context 'with default configuration of local salus.yaml file' do
      it 'runs and exits failure since the overall scan failed' do
        Dir.chdir('spec/fixtures/salus/failure') do
          # This should hit the local config file which enforces a failing pattern search.
          expect(Salus.scan(quiet: true)).to eq(Salus::EXIT_FAILURE)
        end
      end
    end

    context 'with configuration argument' do
      it 'runs and exits failure since the overall scan failed' do
        Dir.chdir('spec/fixtures/salus/success') do
          expect(
            Salus.scan(config: 'file:///failure_salus.yaml', quiet: true)
          ).to eq(Salus::EXIT_FAILURE)
        end
      end
    end

    context 'with configuration envars' do
      it 'runs and exits failure since the overall scan failed' do
        Dir.chdir('spec/fixtures/salus/success') do
          ENV['SALUS_CONFIGURATION'] = 'file:///failure_salus.yaml'
          expect(Salus.scan(quiet: true)).to eq(Salus::EXIT_FAILURE)
        end
      end
    end

    context 'with plugin and configuration build hash' do
      it 'applies the plugin custom logic to the config' do
        Dir.chdir('spec/fixtures/salus/plugin_config') do
          ENV['SALUS_CONFIGURATION'] = 'file:///salus.yaml'

          expect(Salus::Report).to receive(:new).with(report_uris: anything,
            builds: anything,
            project_name: 'raboof',
            custom_info: anything,
            config: anything).at_least(:once).and_call_original

          expect(Salus.scan(quiet: true)).to eq(Salus::EXIT_SUCCESS)
        end
      end
    end

    context 'With heartbeat set' do
      it 'outputs a heartbeat' do
        Dir.chdir('spec/fixtures/salus/success') do
          expect { Salus.scan }.to output(/Salus is running\.$/).to_stdout
        end
      end
    end

    context 'With no heartbeat set' do
      it 'does not produce a heartbeat when quiet is enabled' do
        Dir.chdir('spec/fixtures/salus/success') do
          expect { Salus.scan(quiet: true) }.to_not output(/Salus is running\.$/).to_stdout
        end
      end

      it 'does not produce a heartbeat when heartbeat is disabled' do
        Dir.chdir('spec/fixtures/salus/success') do
          expect { Salus.scan(heartbeat: false) }.to_not output(/Salus is running\.$/).to_stdout
        end
      end

      it 'does not produce a heartbeat when quiet is enabled and heartbeat is disabled' do
        Dir.chdir('spec/fixtures/salus/success') do
          expect { Salus.scan(quiet: true, heartbeat: false) }
            .to_not output(/Salus is running\.$/).to_stdout
        end
      end
    end
  end
end
