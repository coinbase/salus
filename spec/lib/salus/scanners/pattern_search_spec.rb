require_relative '../../../spec_helper.rb'

describe Salus::Scanners::PatternSearch do
  describe '#run' do
    context 'no forbidden regex' do
      it 'should report matches' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = { 'matches' => [{ 'regex' => 'Nerv', 'forbidden' => false }] }
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          regex: 'Nerv',
          forbidden: false,
          required: false,
          msg: '',
          hit: 'lance.txt:3:Nerv housed the lance.'
        )

        expect(info[:hits]).to include(
          regex: 'Nerv',
          forbidden: false,
          required: false,
          msg: '',
          hit: 'seal.txt:3:Nerv is tasked with taking over when the UN fails.'
        )

        expect(info[:misses]).to be_empty
      end

      it 'should report matches with a message' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = {
          'matches' => [
            {
              'regex' => 'Nerv',
              'message' => "Shaken, not stirred.",
              'forbidden' => false
            }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          regex: 'Nerv',
          forbidden: false,
          required: false,
          msg: 'Shaken, not stirred.',
          hit: 'lance.txt:3:Nerv housed the lance.'
        )

        expect(info[:hits]).to include(
          regex: 'Nerv',
          forbidden: false,
          required: false,
          msg: 'Shaken, not stirred.',
          hit: 'seal.txt:3:Nerv is tasked with taking over when the UN fails.'
        )

        expect(info[:misses]).to be_empty
      end
    end

    context 'some regex hits are forbidden' do
      it 'should report matches' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = { 'matches' => [{ 'regex' => 'Nerv', 'forbidden' => true }] }
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          regex: 'Nerv',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'lance.txt:3:Nerv housed the lance.'
        )
        expect(info[:misses]).to be_empty

        logs = scanner.report.to_h.fetch(:logs)
        failure_str = 'seal.txt:3:Nerv is tasked with taking over when the UN fails'
        expect(logs).to include(failure_str)
        expect(info[:hits]).to include(
          regex: 'Nerv',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'seal.txt:3:Nerv is tasked with taking over when the UN fails.'
        )
        expect(info[:misses]).to be_empty
      end
    end

    context 'some regex hits are required' do
      it 'should pass the scan if a required patterns are found' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = {
          'matches' => [
            { 'regex' => 'Nerv', 'required' => true, 'message' => 'important string' }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          regex: 'Nerv',
          forbidden: false,
          required: true,
          msg: 'important string',
          hit: 'lance.txt:3:Nerv housed the lance.'
        )
        expect(info[:misses]).to be_empty
      end

      it 'should failed the scan if a required pattern is not found' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = {
          'matches' => [
            { 'regex' => 'Tokyo3', 'required' => true, 'message' => 'current location' }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        failure_messages = scanner.report.to_h.fetch(:logs)
        expect(failure_messages)
          .to include('Required pattern "Tokyo3" was not found - current location')

        info = scanner.report.to_h.fetch(:info)
        expect(info[:hits]).to be_empty
        expect(info[:misses].size).to eq(1)
        expect(info[:misses]).to include(
          regex: 'Tokyo3',
          forbidden: false,
          required: true,
          msg: 'current location'
        )
      end
    end

    context 'global exclusions are given' do
      it 'should not search through excluded material' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = {
          'matches' => [
            { regex: 'UN' },
            { 'regex' => 'lance', 'forbidden' => true }
          ],
          'exclude_extension' => ['txt']
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)
      end
    end

    context 'local exclusions are given' do
      it 'should not search through excluded material' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = {
          'matches' => [
            { regex: 'UN', 'exclude_extension' => ['txt'] },
            { 'regex' => 'lance', 'forbidden' => true, 'exclude_extension' => ['txt'] }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)
      end

      it 'should not search through excluded extensions' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')

        config = {
          'matches' => [
            { 'regex' => 'UN', 'exclude_extension' => %w[txt md] },
            { 'regex' => 'lance', 'forbidden' => false }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:hits].map { |hit| hit[:regex] }).to_not include('UN')
      end
    end

    context 'global inclusions are given' do
      it 'should search only through included material' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')

        config = {
          'matches' => [
            { regex: 'UN' },
            { 'regex' => 'lance', 'forbidden' => true },
            { regex: 'fancy' }
          ],
          'include_extension' => ['md']
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)
      end
    end

    context 'local inclusions are given' do
      it 'should only search through included material' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')

        config = {
          'matches' => [
            { 'regex' => 'lance', 'forbidden' => true, 'include_extension' => ['md'] }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)
      end

      it 'should not search through extensions not explicitly included' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')

        config = {
          'matches' => [
            { 'regex' => 'UN', 'include_extension' => ['md'] },
            { 'regex' => 'fancy', 'include_extension' => ['md']  }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:hits].map { |hit| hit[:regex] }).to_not include('UN')
        expect(info[:hits].map { |hit| hit[:regex] }).to include('fancy')
      end

      it 'should coexist with exclusions' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = {
          'matches' => [
            { 'regex' => 'fancy', 'include_extension' => ['md']  },
            { 'regex' => 'lance', 'forbidden' => true, 'exclude_extension' => ['txt'], \
              'include_extension' => ['md'] }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:hits].map { |hit| hit[:regex] }).to include('fancy')
      end

      it 'should handle conflicting local exclusions' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = {
          'matches' => [
            { 'regex' => 'fancy', 'include_extension' => ['md'], 'exclude_extension' => ['md'] },
            { 'regex' => 'lance', 'forbidden' => true, 'exclude_extension' => ['txt'], \
              'include_extension' => ['md'] }
          ]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)
        info = scanner.report.to_h.fetch(:info)
        expect(info[:hits].map { |hit| hit[:regex] }).to_not include('fancy')
      end

      it 'should handle conflicting global exclusions' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = {
          'matches' => [
            { 'regex' => 'fancy', 'include_extension' => ['md'] },
            { 'regex' => 'lance', 'forbidden' => true, 'include_extension' => ['md'] }
          ],
          'exclude_extension' => %w[txt md]
        }

        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)
        info = scanner.report.to_h.fetch(:info)
        expect(info[:hits].map { |hit| hit[:regex] }).to_not include('fancy')
      end
    end

    context 'not_followed_within is used' do
      let(:repo_dir) { "spec/fixtures/pattern_search/test_paths3" }
      it 'not_followed_within should filter out files when possible' do
        config_file = "#{repo_dir}/salus.yaml"
        repo = Salus::Repo.new(repo_dir)
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['PatternSearch']
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        # In salus.yaml, "not_followed_within: 0:bye" filters out the "hello bye" in results
        expect(info[:hits]).to eq([{ regex: 'hello',
                                    forbidden: true,
                                    required: false,
                                    msg: '',
                                    hit: 'test.txt:1:hello world' }])
      end
    end

    context '--files is used' do
      let(:repo_dir) { "spec/fixtures/pattern_search/test_paths4" }
      it 'results should only include files matching --files' do
        config_file = "#{repo_dir}/salus.yaml"
        repo = Salus::Repo.new(repo_dir)
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['PatternSearch']
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        # results include only the file names matching "files" in salus.yaml
        expect(info[:hits].size).to eq(2)
        expect(info[:hits]).to include(
          regex: 'hello',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'test.txt:1:hello world'
        )
        expect(info[:hits]).to include(
          regex: 'hello',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'test.py:1:hello world'
        )
      end

      it '--exclude_filepaths should work with --files' do
        config_file = "#{repo_dir}/salus2.yaml"
        repo = Salus::Repo.new(repo_dir)
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['PatternSearch']
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        # salus config excludes txt
        expect(info[:hits]).to eq([{ regex: 'hello',
                                    forbidden: true,
                                    required: false,
                                    msg: '',
                                    hit: 'test.py:1:hello world' }])
      end
    end

    context 'exclude filepaths are given' do
      let(:repo_dir) { "spec/fixtures/pattern_search/test_paths" }

      it 'files specified with exclude_filepaths at the match level  should be excluded' do
        config_file = "#{repo_dir}/salus.yaml"
        repo = Salus::Repo.new(repo_dir)
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['PatternSearch']
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits].size).to eq(1)
        expect(info[:hits]).to include(
          regex: 'hello',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'subdir/subdir2/file.txt:1:hello'
        )
      end

      it 'exclude_paths of the match should override global exclude_filepaths' do
        config_file = "#{repo_dir}/salus2.yaml"
        repo = Salus::Repo.new(repo_dir)
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['PatternSearch']
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits].size).to eq(2)
        expect(info[:hits]).to include(
          regex: 'hello',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'subdir/file.txt:1:hello'
        )
        expect(info[:hits]).to include(
          regex: 'hello',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'subdir/subdir2/file.txt:1:hello'
        )
      end

      it 'files specified with global exclude_filepaths should be excluded' do
        config_file = "#{repo_dir}/salus3.yaml"
        repo = Salus::Repo.new(repo_dir)
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['PatternSearch']
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits].size).to eq(1)
        expect(info[:hits]).to include(
          regex: 'hello',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'subdir/subdir2/file.txt:1:hello'
        )
      end

      it 'exclude_filepaths, exclude_directory, and exclude_extension can be used together' do
        repo_dir = 'spec/fixtures/pattern_search/test_paths2'
        # this config uses exclude_filepaths, exclude_directory, and exclude_extension together
        config_file = "#{repo_dir}/salus.yaml"
        repo = Salus::Repo.new(repo_dir)
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['PatternSearch']
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits].size).to eq(1)
        expect(info[:hits]).to include(
          regex: 'hello',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'file.txt:1:hello'
        )
      end
    end

    context 'invalid regex or settings which causes error' do
      it 'should record the STDERR of bundle-audit' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = { 'matches' => [{ 'regex' => '(', 'forbidden' => true }] }
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        errors = scanner.report.to_h.fetch(:errors)
        expect(errors).to include(
          status: 1,
          stderr:
            "Error: cannot parse pattern: error parsing regexp: missing closing ): `(?m)(`\n",
          message: "Call to sift failed"
        )
      end
    end

    context 'special chars should not be escaped' do
      it 'quotes should not be consumed by shell' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = { 'matches' => [{ 'regex' => 'KEY: [\'"]off[\'"]', 'forbidden' => true }] }
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          regex: "KEY: ['\"]off['\"]",
          forbidden: true,
          required: false,
          msg: '',
          hit: 'special_chars.txt:1:KEY: "off"'
        )
        expect(info[:hits]).to include(
          regex: 'KEY: [\'"]off[\'"]',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'special_chars.txt:2:KEY: \'off\''
        )
      end
    end
  end

  describe '#should_run?' do
    it 'should return true' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::PatternSearch.supported_languages
        expect(langs).to eq(['*'])
      end
    end
  end
end
