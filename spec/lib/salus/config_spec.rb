require_relative '../../spec_helper.rb'

describe Salus::Config do
  let(:config_file_1)            { File.read('spec/fixtures/config/salus.yaml') }
  let(:config_file_2)            { File.read('spec/fixtures/config/salus_extra.yaml') }
  let(:envar_config_file)        { File.read('spec/fixtures/config/envar_config.yaml') }
  let(:custom_info_hash_config_file) { File.read('spec/fixtures/config/custom_info_h.yaml') }
  let(:custom_info_string_config_file) { File.read('spec/fixtures/config/custom_info_s.yaml') }
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
        expect(config.scanner_configs['BundleAudit']).to include('pass_on_raise' => false)
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

    it 'should accept custom_info hashes' do
      config = Salus::Config.new([custom_info_hash_config_file])
      expect(config.custom_info).to be_a(Hash)
      expect(config.custom_info).to include("branch")
    end

    it 'should accept custom_info strings' do
      config = Salus::Config.new([custom_info_string_config_file])
      expect(config.custom_info).to be_a(String)
      expect(config.custom_info).to eq('master')
    end

    it 'should deep merge config files' do
      config = Salus::Config.new([config_file_1, config_file_2])
      expect(config.scanner_configs['BundleAudit']).to include(
        'ignore' => %w[CVE-AAAA-BBBB CVE-XXXX-YYYY],
        'failure_message' => 'Please upgrade the failing dependency.'
      )
    end

    it 'should apply default scanner config for each scanner' do
      config = Salus::Config.new([config_file_1])
      expect(config.scanner_configs.none? { |_, conf| conf['pass_on_raise'] }).to eq(true)

      config = Salus::Config.new([File.read('spec/fixtures/config/salus_pass_on_raise.yaml')])
      expect(config.scanner_configs['BundleAudit']['pass_on_raise']).to eq(true)
    end

    it 'should merge all NodeAudit related configuration' do
      node_audit_config = File.read('spec/fixtures/config/node_audit_config.yaml')
      npm_audit_config = File.read('spec/fixtures/config/npm_audit_config.yaml')
      config = Salus::Config.new([node_audit_config, npm_audit_config])

      expected_config = {
        'foo' => 'bar',    # from NodeAudit config
        'exceptions' => [  # from NPMAudit config
          { 'advisory_id' => '12', 'changed_by' => 'appsec team', 'notes' => 'barfoo' }
        ]
      }

      expect(config.scanner_configs['NodeAudit']).to include(expected_config)
      expect(config.scanner_configs['NPMAudit']).to include(expected_config)
      expect(config.scanner_configs['YarnAudit']).to include(expected_config)
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
