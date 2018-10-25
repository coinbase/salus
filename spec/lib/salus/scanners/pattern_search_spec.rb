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

        expect(info[:hits]).to include(
          regex: 'Nerv',
          forbidden: true,
          required: false,
          msg: '',
          hit: 'seal.txt:3:Nerv is tasked with taking over when the UN fails.'
        )
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

        errors = scanner.report.to_h.fetch(:errors)

        expect(errors)
          .to include(message: 'Required pattern "Tokyo3" was not found - current location')
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

    context 'invalid regex or settings which causes error' do
      it 'should record the STDERR of bundle-audit' do
        repo = Salus::Repo.new('spec/fixtures/pattern_search')
        config = { 'matches' => [{ 'regex' => '(', 'forbidden' => true }] }
        scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        errors = scanner.report.to_h.fetch(:errors)

        expect(errors).to include(
          status: 1,
          stderr:
            "Error: cannot parse pattern: error parsing regexp: missing closing ): `(?m)(`\n",
          message: "Call to sift failed"
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
end
