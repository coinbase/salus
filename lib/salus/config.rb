require 'safe_yaml'
require 'set'

module Salus
  class Config
    # Salus configuration can come from:
    #   - a local salus.yaml file
    #   - a GET to a URI given as a command line arg or envar which returns a YAML file string.
    #
    # The URI format can help security teams update enforced scans or the latest
    # configuration in a centralized manner across all services in their organization.

    attr_reader :project_name,
                :custom_info,
                :report_uris,
                :builds,
                :active_scanners,
                :enforced_scanners,
                :scanner_configs

    # Dynamically get all Scanner classes
    ABSTRACT_SCANNERS = %i[Base NodeAudit].freeze
    SCANNERS = Salus::Scanners.constants
      .reject { |klass| ABSTRACT_SCANNERS.include?(klass) }
      .map { |klass| [klass.to_s, Salus::Scanners.const_get(klass)] }
      .sort
      .to_h
      .freeze

    # This is the base configuration file, and we merge all other configuration
    # provided into this file to create one final configuration.
    DEFAULT_CONFIG = YAML.load_file(
      File.join(File.dirname(__FILE__), '../../salus-default.yaml'),
      safe: true
    ).freeze

    DEFAULT_SCANNER_CONFIG = {
      'pass_on_raise' => false # strong default - if a scanner raises, it counts as failure.
    }.freeze

    LOCAL_FILE_SCHEME_REGEX = /\Afile\z/.freeze # like file://foobar
    REMOTE_URI_SCHEME_REGEX = /\Ahttps?\z/.freeze
    REPORT_FORMATS = %w[txt json yaml sarif].freeze

    def initialize(configuration_files = [])
      # Merge default and custom configuration files.
      # The later files in the array take superiority by overwriting configuration already
      # defined in the earlier files in the array (DEFAULT_CONFIG is the first such file/object).
      final_config = DEFAULT_CONFIG.dup
      configuration_files.each { |file| final_config.deep_merge!(YAML.safe_load(file)) }

      # Check if any of the values are actually pointing to envars.
      final_config = fetch_envars(final_config)

      # Parse and store configuration.
      @active_scanners   = all_none_some(SCANNERS.keys, final_config['active_scanners'])
      @enforced_scanners = all_none_some(SCANNERS.keys, final_config['enforced_scanners'])
      @scanner_configs   = final_config['scanner_configs'] || {}
      @project_name      = final_config['project_name']&.to_s
      @custom_info       = final_config['custom_info']
      @report_uris       = final_config['reports'] || []
      @builds            = final_config['builds'] || {}

      apply_default_scanner_config!
      apply_node_audit_patch!
    end

    def scanner_active?(scanner_class)
      @active_scanners.include?(scanner_class.to_s)
    end

    def scanner_enforced?(scanner_class)
      @enforced_scanners.include?(scanner_class.to_s)
    end

    def to_h
      {
        active_scanners: @active_scanners.to_a.sort,
        enforced_scanners: @enforced_scanners.to_a.sort,
        scanner_configs: @scanner_configs,
        project_name: @project_name,
        custom_info: @custom_info,
        report_uris: @report_uris,
        builds: @builds
      }.compact
    end

    private

    def apply_node_audit_patch!
      # To allow for backwards compatability and easy switching between node package managers,
      # We will remap any NPMAudit and YarnAudit scanner connfigs to NodeAudit.
      return if %w[NodeAudit NPMAudit YarnAudit].map { |k| @scanner_configs.key?(k) }.none?

      # Make a fully merged config hash for NodeAudit.
      @scanner_configs['NodeAudit'] ||= {}
      @scanner_configs['NodeAudit'].deep_merge!(@scanner_configs['NPMAudit'] || {})
      @scanner_configs['NodeAudit'].deep_merge!(@scanner_configs['YarnAudit'] || {})

      # Copy over the config to the relevant scanners to ensure they all inherit it.
      @scanner_configs['NPMAudit'] = @scanner_configs['NodeAudit']
      @scanner_configs['YarnAudit'] = @scanner_configs['NodeAudit']
    end

    # Applies default scanner config for anything not already defined.
    def apply_default_scanner_config!
      SCANNERS.each_key do |scanner|
        @scanner_configs[scanner] ||= {}
        @scanner_configs[scanner] = DEFAULT_SCANNER_CONFIG
          .dup
          .deep_merge!(@scanner_configs[scanner])
      end
    end

    def fetch_envars(config_hash)
      return config_hash if ENV['RUNNING_SALUS_TESTS']

      # Get the configuration back into string format
      config_string = YAML.dump(config_hash)

      # Check for references to evnars.
      envar_refs = config_string.scan(/\{\{([_a-zA-Z0-9]+)\}\}/).flatten

      # Replace all references to envars.
      envar_refs.each do |envar_name|
        config_string.gsub!("{{#{envar_name}}}", ENV[envar_name]) if ENV[envar_name]
      end

      # Return the config object.
      YAML.safe_load(config_string)
    end

    def all_none_some(superset, subset)
      if subset == 'all'
        Set.new(superset) # entire set
      elsif subset == 'none'
        Set.new           # empty set
      elsif subset.is_a?(Array)
        Set.new(subset)   # subset
      else
        raise ArgumentError
      end
    end
  end
end
