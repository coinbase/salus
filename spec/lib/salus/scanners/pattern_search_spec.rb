require_relative '../../../spec_helper.rb'

describe Salus::Scanners::PatternSearch do
  let(:report) { Salus::Report.new }
  let(:scan_report) { json_report['scans']['PatternSearch'] }

  describe '#run' do
    context 'no forbidden regex' do
      it 'should report matches' do
        scanner = Salus::Scanners::PatternSearch.new(
          repository: Salus::Repo.new('spec/fixtures/pattern_search'),
          report: report,
          config: { 'matches' => [{ 'regex' => 'Nerv', 'forbidden' => false }] }
        )
        scanner.run
        expect(scan_report['info']['pattern_search_hit']).to include(
          'regex' => 'Nerv',
          'forbidden' => false,
          'required' => false,
          'msg' => '',
          'hit' => 'lance.txt:3:Nerv housed the lance.'
        )
        expect(scan_report['info']['pattern_search_hit']).to include(
          'regex' => 'Nerv',
          'forbidden' => false,
          'required' => false,
          'msg' => '',
          'hit' => 'seal.txt:3:Nerv is tasked with taking over when the UN fails.'
        )
        expect(scan_report['passed']).to eq(true)
      end

      it 'should report matches with a message' do
        scanner = Salus::Scanners::PatternSearch.new(
          repository: Salus::Repo.new('spec/fixtures/pattern_search'),
          report: report,
          config: {
            'matches' => [
              {
                'regex' => 'Nerv',
                'message' => "Shaken, not stirred.",
                'forbidden' => false
              }
            ]
          }
        )
        scanner.run
        expect(scan_report['info']['pattern_search_hit']).to include(
          'regex' => 'Nerv',
          'forbidden' => false,
          'required' => false,
          'msg' => 'Shaken, not stirred.',
          'hit' => 'lance.txt:3:Nerv housed the lance.'
        )
        expect(scan_report['info']['pattern_search_hit']).to include(
          'regex' => 'Nerv',
          'forbidden' => false,
          'required' => false,
          'msg' => 'Shaken, not stirred.',
          'hit' => 'seal.txt:3:Nerv is tasked with taking over when the UN fails.'
        )
        expect(scan_report['passed']).to eq(true)
      end
    end

    context 'some regex hits are forbidden' do
      it 'should report matches' do
        scanner = Salus::Scanners::PatternSearch.new(
          repository: Salus::Repo.new('spec/fixtures/pattern_search'),
          report: report,
          config: { 'matches' => [{ 'regex' => 'Nerv', 'forbidden' => true }] }
        )
        scanner.run
        expect(scan_report['info']['pattern_search_hit']).to include(
          'regex' => 'Nerv',
          'forbidden' => true,
          'required' => false,
          'msg' => '',
          'hit' => 'lance.txt:3:Nerv housed the lance.'
        )
        expect(scan_report['info']['pattern_search_hit']).to include(
          'regex' => 'Nerv',
          'forbidden' => true,
          'required' => false,
          'msg' => '',
          'hit' => 'seal.txt:3:Nerv is tasked with taking over when the UN fails.'
        )
        expect(scan_report['passed']).to eq(false)
      end
    end

    context 'some regex hits are required' do
      it 'should pass the scan if a required patterns are found' do
        scanner = Salus::Scanners::PatternSearch.new(
          repository: Salus::Repo.new('spec/fixtures/pattern_search'),
          report: report,
          config: {
            'matches' => [
              { 'regex' => 'Nerv', 'required' => true, 'message' => 'important string' }
            ]
          }
        )

        scanner.run

        expect(scan_report['info']['pattern_search_hit']).to include(
          'regex' => 'Nerv',
          'forbidden' => false,
          'required' => true,
          'msg' => 'important string',
          'hit' => 'lance.txt:3:Nerv housed the lance.'
        )
        expect(scan_report['passed']).to eq(true)
      end

      it 'should pass the scan if a required patterns are found' do
        scanner = Salus::Scanners::PatternSearch.new(
          repository: Salus::Repo.new('spec/fixtures/pattern_search'),
          report: report,
          config: {
            'matches' => [
              { 'regex' => 'Tokyo3', 'required' => true, 'message' => 'current location' }
            ]
          }
        )

        scanner.run

        expect(scan_report['info']['pattern_search_hit']).to include(
          'Required pattern "Tokyo3" was not found - current location'
        )
        expect(scan_report['passed']).to eq(false)
      end
    end

    context 'global exclusions are given' do
      it 'should not search through excluded material' do
        scanner = Salus::Scanners::PatternSearch.new(
          repository: Salus::Repo.new('spec/fixtures/pattern_search'),
          report: report,
          config: {
            'matches' => [
              { 'regex' => 'UN' },
              { 'regex' => 'lance', 'forbidden' => true }
            ],
            'exclude_extension' => ['txt']
          }
        )
        scanner.run
        expect(scan_report['info']).to eq(nil)
        expect(scan_report['passed']).to eq(true)
      end
    end

    context 'local exclusions are given' do
      it 'should not search through excluded material' do
        scanner = Salus::Scanners::PatternSearch.new(
          repository: Salus::Repo.new('spec/fixtures/pattern_search'),
          report: report,
          config: {
            'matches' => [
              { 'regex' => 'UN', 'exclude_extension' => ['txt'] },
              { 'regex' => 'lance', 'forbidden' => true, 'exclude_extension' => ['txt'] }
            ]
          }
        )
        scanner.run
        expect(scan_report['info']).to eq(nil)
        expect(scan_report['passed']).to eq(true)
      end

      it 'should not search through excluded extensions' do
        scanner = Salus::Scanners::PatternSearch.new(
          repository: Salus::Repo.new('spec/fixtures/pattern_search'),
          report: report,
          config: {
            'matches' => [
              { 'regex' => 'UN', 'exclude_extension' => %w[txt md] },
              { 'regex' => 'lance', 'forbidden' => false }
            ]
          }
        )
        scanner.run
        expect(scan_report['info']['pattern_search_hit']).to_not include(
          'regex' => 'UN',
          'forbidden' => false,
          'msg' => '',
          'hit' => 'seal.txt:3:Nerv is tasked with taking over when the UN fails.'
        )
        expect(scan_report['passed']).to eq(true)
      end
    end

    context 'invalid regex or settings which causes error' do
      it 'should record the STDERR of bundle-audit' do
        scanner = Salus::Scanners::PatternSearch.new(
          repository: Salus::Repo.new('spec/fixtures/pattern_search'),
          report: report,
          config: { 'matches' => [{ 'regex' => '(', 'forbidden' => true }] }
        )
        scanner.run
        expect(scan_report['stderr']).to include(
          "Error: cannot parse pattern: error parsing regexp: missing closing ): `(?m)(`\n"
        )
        expect(scan_report['passed']).to eq(true) # we did not hit any forbidden errors.
      end
    end
  end

  describe '#should_run?' do
    it 'should return true' do
      scanner = Salus::Scanners::PatternSearch.new(
        repository: Salus::Repo.new('spec/fixtures/blank_repository'),
        report: report,
        config: {}
      )
      expect(scanner.should_run?).to eq(true)
    end
  end
end
