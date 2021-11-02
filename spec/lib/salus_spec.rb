require 'fileutils'
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

    context 'local_uri paths' do
      it 'should not write local report bad file path' do
        Dir.chdir('spec/fixtures/repo2') do
          # report path is outside repo dir
          ENV['SALUS_CONFIGURATION'] = 'file://salus.yaml'
          expect do
            Salus.scan(repo_path: '.', quiet: true)
          end.to raise_error(StandardError)
          expect(File).not_to exist('../out1.json')

          # report path is ..out1.json
          ENV['SALUS_CONFIGURATION'] = 'file:///salus4.yaml'
          expect do
            Salus.scan(repo_path: '.', quiet: true)
          end.to raise_error(StandardError)
          expect(File).not_to exist('..out1.json')

          # report path is .out1.json
          ENV['SALUS_CONFIGURATION'] = 'file:///salus4.yaml'
          expect do
            Salus.scan(repo_path: '.', quiet: true)
          end.to raise_error(StandardError)
          expect(File).not_to exist('.out1.json')
        end
      end

      it 'should write to local report if good file path' do
        Dir.chdir('spec/fixtures/repo2') do
          ENV['SALUS_CONFIGURATION'] = 'file:///salus2.yaml'
          Salus.scan(repo_path: '.', quiet: true)
          expect(File).to exist('out1.json')
          remove_file('out1.json')

          ENV['SALUS_CONFIGURATION'] = 'file:///salus3.yaml'
          Salus.scan(repo_path: '.', quiet: true)
          expect(File).to exist('out1.json')
          remove_file('out1.json')
        end
      end
    end

    context 'With --sarif_diff_full' do
      it 'Should ouput full sarif diff of two files' do
        Dir.chdir('spec/fixtures/sarifs/diff') do
          args = ['sarif_1.json', 'sarif_2.json']
          ENV['SALUS_CONFIGURATION'] = 'file:///salus_diff.yaml'
          Salus.scan(quiet: true, repo_path: '.', sarif_diff_full: args)
          diff_file = 'diff_1_2.json'
          expect(File).to exist(diff_file)
          diff_sarif = JSON.parse(File.read(diff_file))
          expected_sarif = JSON.parse(File.read('diff_1_2.json'))
          expect(expected_sarif).to eq(diff_sarif)
        end
      end

      it 'Should report error if invalid arguments used for option' do
        Dir.chdir('spec/fixtures/sarifs/diff') do
          expect do # two sarifs should be provided for sarif diff
            Salus.scan(quiet: true, repo_path: '.', sarif_diff_full: ['sarif_1.json'])
          end.to raise_error

          expect do # file names should not be outside repo dir
            args = ['sarif_1.json', '../sarif_2.json']
            Salus.scan(quiet: true, repo_path: '.', sarif_diff_full: args)
          end.to raise_error
        end
      end
    end

    context 'With --filter_sarif' do
      it 'Should ouput filtered vulnerabilities' do
        Dir.chdir('spec/fixtures/gosec/multiple_vulns2') do
          ENV['SALUS_CONFIGURATION'] = 'file:///salus.yaml'
          Salus.scan(quiet: true, repo_path: '.', filter_sarif: 'filter.sarif')
          diff_file = 'salus_sarif_diff.json' # filtered results
          sarif_file = 'out.sarif' # full results
          expect(File).to exist(diff_file)
          expect(File).to exist(sarif_file)

          data = JSON.parse(File.read(sarif_file))
          results = data['runs'][0]['results']
          rule_ids = results.map { |r| r['ruleId'] }.sort
          expect(rule_ids).to eq(%w[G101 G104 G401 G501])

          # filtered result file should include both new rules and project build info
          data = JSON.parse(File.read(diff_file))
          expect(data['report_type']).to eq('salus_sarif_diff')
          rule_ids = data['filtered_results'].map { |r| r['ruleId'] }.sort

          expect(rule_ids).to eq(%w[G401 G501])
          builds = data['builds']
          expect(builds['org']).to eq('my_org')
          expect(builds['project']).to eq('my_repo')
          expect(builds['url']).to eq('http://buildkite/builds/123456')
        end
      end
    end

    context 'With --ignore_config_id' do
      it 'Should filter out report ids' do
        Dir.chdir('spec/fixtures/config') do
          # These salus configs write json, sarif, and txt

          ENV['SALUS_CONFIGURATION'] = 'file:///multiple_reports.yaml'
          Salus.scan(quiet: true, repo_path: '.')
          expect(File).to exist('out.sarif')
          expect(File).to exist('out.json')
          expect(File).to exist('out.txt')

          ENV['SALUS_CONFIGURATION'] = 'file:///multiple_reports2.yaml'
          Salus.scan(quiet: true, repo_path: '.', ignore_config_id: 'reports:txt')
          expect(File).to exist('out2.sarif')
          expect(File).to exist('out2.json')
          expect(File).not_to exist('out2.txt')

          ENV['SALUS_CONFIGURATION'] = 'file:///multiple_reports3.yaml'
          Salus.scan(quiet: true, repo_path: '.', ignore_config_id: 'reports:txt,reports:json')
          expect(File).to exist('out3.sarif')
          expect(File).not_to exist('out3.json')
          expect(File).not_to exist('out3.txt')
        end
      end
    end

    context 'With plugins' do
      it 'should send scan event' do
        Dir.chdir('spec/fixtures/blank_repository2') do
          expect(Salus::PluginManager).to receive(:send_event).at_least(:once)
          Salus.scan(quiet: true, repo_path: '.')
        end
      end

      it 'Should update config based on plugin' do
        Dir.chdir('spec/fixtures/blank_repository2') do
          plugin_dir = File.join(__dir__, '../fixtures/blank_repository2/test_plugins')
          ENV['SALUS_CONFIGURATION'] = 'file:///salus.yaml'
          expect(Salus::PluginManager).to receive(:plugin_dir).and_return(plugin_dir)
            .at_least(:once)
          Salus.scan(quiet: true, repo_path: '.')
          expect(File).to exist('out.json')

          json_content = JSON.parse(File.read('out.json'))
          builds = json_content['config']['builds']
          expected_builds = { "abc" => "xyz",
                              "abcd" => "xyzw",
                              "service_name" => "circle_CI",
                              "url" => "my_url",
                              "mykey" => "myval" }
          expect(builds).to eq(expected_builds)
        end
      end
    end
  end
end
