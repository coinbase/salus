require_relative '../../../spec_helper.rb'
require 'json'

# rubocop:disable Layout/LineLength
describe Salus::Scanners::Brakeman do
  let(:fixture_path) { File.expand_path("../../../../spec/fixtures/brakeman", __dir__) }

  describe '#run' do
    context 'non-rails project' do
      it 'should record the STDERR of brakeman' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})

        expect(scanner.should_run?).to eq(false)

        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:stderr]).to include('Please supply the path to a Rails application')
      end
    end

    context 'brakeman configs' do
      before(:each) do
        allow(Date).to receive(:today).and_return Date.new(2021, 12, 31)
      end

      it 'should error if no top-level app dir and no user defined app path' do
        repo = Salus::Repo.new('spec/fixtures/')
        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:stderr]).to include('Please supply the path to a Rails application')
      end

      it 'should respect the config for user defined app path if no top-level app dir' do
        repo = Salus::Repo.new('spec/fixtures/')
        path = File.join(fixture_path, 'vulnerable_rails_app')

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: { 'path' => path })
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).to include('Dangerous Eval')
        parsed_logs = JSON.parse(logs)
        expect(parsed_logs["scan_info"]["app_path"]).to eq(path)
      end

      it 'should respect brakeman.ignore files' do
        repo = Salus::Repo.new(File.join(fixture_path, 'vulnerable_rails_app'))

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {
                                                  'ignore' => File.join(fixture_path,
                                                                        'vulnerable_rails_app',
                                                                        'brakeman.ignore')
                                                })
        scanner.run

        expect(scanner.report.passed?).to eq(true)
        info = scanner.report.to_h.fetch(:info)
        expect(info[:stdout]).to be_nil
      end

      it 'should respect expirations from brakeman.ignore files' do
        repo = Salus::Repo.new(File.join(fixture_path, 'vulnerable_rails_app'))
        config = {
          'ignore' => File.join(fixture_path,
                                'vulnerable_rails_app',
                                'brakeman-expiration.ignore')
        }
        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)
        logs = scanner.report.to_h.fetch(:logs)
        parsed_logs = JSON.parse(logs)
        expect(parsed_logs['warnings'].size).to eq(2)
      end

      it 'should support exceptions' do
        repo = Salus::Repo.new(File.join(fixture_path, 'vulnerable_rails_app'))
        exceptions = [{ 'advisory_id' => 'b16e1cd0d952433f80b0403b6a74aab0e98792ea015cc1b1fa5c003cbe7d56eb',
                                                                    'notes' => 'Good reason to skip' },
                      { 'advisory_id' => 'c8697fda60549ca065789e2ea74c94effecef88b2b5483bae17ddd62ece47194',
                       'notes' => 'Good reason to skip' },
                      { 'advisory_id' => 'c8adc1c0caf2c9251d1d8de588fb949070212d0eed5e1580aee88bab2287b772',
                       'notes' => 'Good reason to skip' },
                      { 'advisory_id' => 'e0636b950dd005468b5f9a0426ed50936e136f18477ca983cfc51b79e29f6463',
                       'notes' => 'Good reason to skip' }]
        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {
                                                  'exceptions' => exceptions
                                                })
        scanner.run
        expect(scanner.report.passed?).to eq(true)
        info = scanner.report.to_h.fetch(:info)
        expect(info[:stdout]).to be_nil
      end

      it 'should report an error if unable to create temporary ignore' do
        allow(Tempfile).to receive(:create).and_raise(Errno::EROFS)

        repo = Salus::Repo.new(File.join(fixture_path, 'vulnerable_rails_app'))
        exceptions = [{ 'advisory_id' => 'b16e1cd0d952433f80b0403b6a74aab0e98792ea015cc1b1fa5c003cbe7d56eb',
                                                                    'notes' => 'Good reason to skip' },
                      { 'advisory_id' => 'c8697fda60549ca065789e2ea74c94effecef88b2b5483bae17ddd62ece47194',
                       'notes' => 'Good reason to skip' },
                      { 'advisory_id' => 'c8adc1c0caf2c9251d1d8de588fb949070212d0eed5e1580aee88bab2287b772',
                       'notes' => 'Good reason to skip' },
                      { 'advisory_id' => 'e0636b950dd005468b5f9a0426ed50936e136f18477ca983cfc51b79e29f6463',
                       'notes' => 'Good reason to skip' }]
        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {
                                                  'exceptions' => exceptions
                                                })
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        errors = [{ message: "Read only filesystem, unable to apply exceptions" }]
        expect(scanner.report.errors).to eq(errors)
      end

      it 'should support expirations in exceptions' do
        repo = Salus::Repo.new(File.join(fixture_path, 'vulnerable_rails_app'))
        exceptions = [{ 'advisory_id' => 'b16e1cd0d952433f80b0403b6a74aab0e98792ea015cc1b1fa5c003cbe7d56eb',
                                          'notes' => 'One good reason to skip' },
                      { 'advisory_id' => 'c8697fda60549ca065789e2ea74c94effecef88b2b5483bae17ddd62ece47194',
                       'notes' => 'Two good reasons to skip' },
                      { 'advisory_id' => 'c8adc1c0caf2c9251d1d8de588fb949070212d0eed5e1580aee88bab2287b772',
                       'notes' => 'Three ood reasons to skip', 'expiration' => '2000-12-31' },
                      { 'advisory_id' => 'e0636b950dd005468b5f9a0426ed50936e136f18477ca983cfc51b79e29f6463',
                       'notes' => 'Four ood reasons to skip', 'expiration' => '2000-12-31' }]
        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {
                                                  'exceptions' => exceptions
                                                })
        scanner.run
        expect(scanner.report.passed?).to eq(false)
        logs = scanner.report.to_h.fetch(:logs)
        parsed_logs = JSON.parse(logs)
        expect(parsed_logs['warnings'].size).to eq(2)
      end

      it 'should support merging exceptions with brakeman.ignore files' do
        repo = Salus::Repo.new(File.join(fixture_path, 'vulnerable_rails_app'))
        exceptions = [{ 'advisory_id' => 'c8adc1c0caf2c9251d1d8de588fb949070212d0eed5e1580aee88bab2287b772',
                            'notes' => 'Good reason to skip' },
                      { 'advisory_id' => 'e0636b950dd005468b5f9a0426ed50936e136f18477ca983cfc51b79e29f6463',
                       'notes' => 'Good reason to skip' }]
        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {
                                                  'ignore' => File.join(fixture_path,
                                                                        'vulnerable_rails_app',
                                                                        'brakeman-partial.ignore'),
          'exceptions' => exceptions
                                                })
        scanner.run
        expect(scanner.report.passed?).to eq(true)
        info = scanner.report.to_h.fetch(:info)
        expect(info[:stdout]).to be_nil
      end

      it 'should respect the config for user defined app path' do
        repo = Salus::Repo.new('spec/fixtures/')
        path = File.join(fixture_path, 'vulnerable_rails_app')

        scanner = Salus::Scanners::Brakeman.new(
          repository: repo,
          config: {
            'path' => path
          }
        )
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).to include('Dangerous Eval')
        parsed_logs = JSON.parse(logs)
        expect(parsed_logs["scan_info"]["app_path"]).to eq(path)
      end

      it 'should respect the config for all checks' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/vulnerable_rails_app')
        scanner = Salus::Scanners::Brakeman.new(
          repository: repo,
          config: {
            'all' => true
          }
        )
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).to include('Dangerous Eval')
        parsed_logs = JSON.parse(logs)
        expect(parsed_logs["scan_info"]["checks_performed"]).to include("ReverseTabnabbing")
      end

      it 'should respect the config for running only a subset of checks' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/vulnerable_rails_app')
        scanner = Salus::Scanners::Brakeman.new(
          repository: repo,
          config: {
            'test' => [
              "Evaluation"
            ]
          }
        )
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).to include('Dangerous Eval')
        parsed_logs = JSON.parse(logs)
        expect(parsed_logs["scan_info"]["checks_performed"]).not_to include("SanitizeMethods")
        expect(parsed_logs["scan_info"]["checks_performed"]).to include("Evaluation")
      end

      it 'should respect the config excluding some checks' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/vulnerable_rails_app')
        scanner = Salus::Scanners::Brakeman.new(
          repository: repo,
          config: {
            'except' => [
              "Evaluation"
            ]
          }
        )
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).not_to include('Dangerous Eval')
        parsed_logs = JSON.parse(logs)
        expect(parsed_logs["scan_info"]["checks_performed"]).to include("SanitizeMethods")
        expect(parsed_logs["scan_info"]["checks_performed"]).not_to include("Evaluation")
      end

      it 'should respect the config supressing warning levels' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/vulnerable_rails_app')
        scanner = Salus::Scanners::Brakeman.new(
          repository: repo,
          config: {
            'warning' => '3'
          }
        )
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).to include('Dangerous Eval')
        expect(logs).not_to include('loofah gem 2.0.3 is vulnerable')
      end

      it 'should respect the config for ignoring files' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/vulnerable_rails_app')

        scanner = Salus::Scanners::Brakeman.new(
          repository: repo,
          config: {
            'skip-files' => ['app/controllers/static_controller_controller.rb']
          }
        )
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).not_to include('Dangerous Eval')
      end

      it 'should respect the config for only scanning certain files' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/vulnerable_rails_app')

        scanner = Salus::Scanners::Brakeman.new(
          repository: repo,
          config: {
            'only-files' => ['app/controllers/application_controller.rb']
          }
        )
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).not_to include('Dangerous Eval')
      end
    end

    context 'brakeman warnings or errors' do
      it 'should fail if a potential vulnerability is detected in the repo' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/vulnerable_rails_app')

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)

        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).to include('Dangerous Eval')
      end

      it 'should fail if brakeman encounters a parse error' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/rails_app_with_syntax_error')

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)

        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        expect(logs).to include('parse error')
      end
    end

    it 'runs cleanly against a project bundled with Bundler 2' do
      repo = Salus::Repo.new('spec/fixtures/brakeman/bundler_2')
      scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
      scanner.run
      expect(scanner.report.passed?).to eq(true)
    end
  end

  describe '#should_run?' do
    context 'no Gemfile nor Rails gem' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.gemfile_present?).to eq(false)

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'Gemfile present but no rails gem' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/ruby_app')
        expect(repo.gemfile_present?).to eq(true)
        expect(repo.gemfile).not_to match(/('|")rails('|")/)

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'Gemfile present with rails gem' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/safe_rails_app')
        expect(repo.gemfile_present?).to eq(true)
        expect(repo.gemfile).to match(/('|")rails('|")/)

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(true)
      end
    end

    context 'Gemfile present with rails gem but no rails app' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/brakeman/ruby_app_with_rails_gem')
        expect(repo.gemfile_present?).to eq(true)
        expect(repo.gemfile).to match(/('|")rails('|")/)

        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(false)
      end
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::Brakeman.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return ruby' do
        langs = Salus::Scanners::Brakeman.supported_languages
        expect(langs).to eq(['ruby'])
      end
    end
  end
end
# rubocop:enable Layout/LineLength
