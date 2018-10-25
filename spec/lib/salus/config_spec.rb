require_relative '../../spec_helper.rb'

describe Salus::Config do
  let(:config_file_1)            { File.read('spec/fixtures/config/salus.yaml') }
  let(:config_file_2)            { File.read('spec/fixtures/config/salus_extra.yaml') }
  let(:envar_config_file)        { File.read('spec/fixtures/config/envar_config.yaml') }
  let(:expected_report_uris) do
    [
      {
        'uri' => 'https://example.com/salus-report',
        'format' => 'json',
        'verbose' => true
      },
      {
        'uri' => 'file://salus-report.txt',
        'format' => 'txt',
        'verbose' => false
      }
    ]
  end

  describe '#initialize' do
    context 'no initialization file given' do
      it 'should use the default config file' do
        config = Salus::Config.new
        expect(config.project_name).to be_nil
        expect(config.custom_info).to be_nil
        expect(config.active_scanners).to eq(Set.new(Salus::Config::SCANNERS.keys))
        expect(config.enforced_scanners).not_to be_empty
        expect(config.scanner_configs).to be_empty
      end
    end

    context 'files given as source' do
      it 'should use the YAML files as config with ordered priority' do
        config = Salus::Config.new([config_file_1])
        expect(config.active_scanners).to eq(Set.new(Salus::Config::SCANNERS.keys))
        expect(config.enforced_scanners).to eq(Set.new(%w[BundleAudit Brakeman]))

        config = Salus::Config.new([config_file_1, config_file_2])
        expect(config.active_scanners).to eq(Set.new(Salus::Config::SCANNERS.keys))
        expect(config.enforced_scanners).to eq(Set.new(%w[BundleAudit ExtraScanner]))
      end
    end

    context 'files point to envars that need to be interpolated' do
      it 'should replace references to envars with the envar values' do
        allow(ENV).to receive(:[]).and_call_original # allow calls in general
        allow(ENV).to receive(:[]).with('RUNNING_SALUS_TESTS').and_return(nil) # otherwise aborts
        allow(ENV).to receive(:[]).with('PROJECT_NAME').and_return('Microvac')
        allow(ENV).to receive(:[]).with('PROJECT_AUTHOR').and_return('Asimov')
        allow(ENV).to receive(:[]).with('PROJECT_DATE').and_return('1956')
        allow(ENV).to receive(:[]).with('REPORT_URI').and_return('https://example.com/salus')

        config = Salus::Config.new([envar_config_file])

        expect(config.project_name).to eq('Microvac')
        expect(config.custom_info).to eq('Asimov-1956')
        expect(config.report_uris).to match_array(
          [
            {
              'uri' => 'https://example.com/salus',
              'format' => 'json',
              'verbose' => true
            }
          ]
        )
      end
    end
  end

  describe '#scanner_active?' do
    it 'should correctly answer if a scanner is active' do
      config = Salus::Config.new
      expect(config.scanner_active?('BundleAudit')).to eq(true)
      expect(config.scanner_active?('UnknownScanner')).to eq(false)
    end
  end

  describe '#scanner_enforced?' do
    it 'should correctly answer if the current configuration has enforced scanning' do
      config = Salus::Config.new([config_file_1])
      expect(config.scanner_enforced?('BundleAudit')).to eq(true)
      expect(config.scanner_enforced?('UnknownScanner')).to eq(false)
    end
  end
end
