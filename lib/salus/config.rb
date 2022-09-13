require 'safe_yaml'
require 'set'
require 'merge_util'

module Salus
  class Config
    # Salus configuration can come from:
    #   - a local salus.yaml file
    #   - a GET to a URI given as a command line arg or envar which returns a YAML file string.
    #
    # The URI format can help security teams update enforced scans or the latest
    # configuration in a centralized manner across all services in their organization.

    include Salus::SalusBugsnag

    attr_reader :project_name,
                :custom_info,
                :report_uris,
                :builds,
                :enforced_scanners,
                :scanner_configs

    attr_accessor :active_scanners

    ABSTRACT_SCANNERS = %i[Base NodeAudit LanguageVersion PackageVersion OSV].freeze

    PACKAGE_VERSION_SCANNERS = Salus::Scanners::PackageVersion.constants
      .reject { |klass| ABSTRACT_SCANNERS.include?(klass) }
      .map { |klass| [klass.to_s, Salus::Scanners::PackageVersion.const_get(klass)] }
    # Dynamically get all Scanners for language version checking
    LANGUAGE_VERSION_SCANNERS = Salus::Scanners::LanguageVersion.constants
      .reject { |klass| ABSTRACT_SCANNERS.include?(klass) }
      .map { |klass| [klass.to_s, Salus::Scanners::LanguageVersion.const_get(klass)] }
    OSV_SCANNERS = Salus::Scanners::OSV.constants
      .reject { |klass| ABSTRACT_SCANNERS.include?(klass) }
      .map { |klass| [klass.to_s, Salus::Scanners::OSV.const_get(klass)] }

    # Dynamically get all other Scanner classes
    OTHER_SCANNERS = Salus::Scanners.constants
      .reject { |klass| ABSTRACT_SCANNERS.include?(klass) }
      .map { |klass| [klass.to_s, Salus::Scanners.const_get(klass)] }

    SCANNERS = (OSV_SCANNERS + PACKAGE_VERSION_SCANNERS +
      LANGUAGE_VERSION_SCANNERS + OTHER_SCANNERS).sort.to_h
      .freeze

    # This is the base configuration file, and we merge all other configuration
    # provided into this file to create one final configuration.
    DEFAULT_CONFIG = YAML.load_file(
      File.join(File.dirname(__FILE__), '../../salus-default.yaml'),
      safe: true
    ).freeze

    DEFAULT_SCANNER_CONFIG = {
      'pass_on_raise' => false, # strong default - if a scanner raises, it counts as failure.
      'scanner_timeout_s' => 0 # Scanner can run indefinitely if a max lifespan isn't provided
    }.freeze

    LOCAL_FILE_SCHEME_REGEX = /\Afile\z/.freeze # like file://foobar
    REMOTE_URI_SCHEME_REGEX = /\Ahttps?\z/.freeze
    REPORT_FORMATS = %w[txt json yaml sarif].freeze

    def initialize(configuration_files = [], ignore_ids = [])
      # Merge default and custom configuration files.
      # The later files in the array take superiority by overwriting configuration already
      # defined in the earlier files in the array (DEFAULT_CONFIG is the first such file/object).
      final_config = DEFAULT_CONFIG.dup
      configuration_files.each do |file|
        file_content = YAML.safe_load(file)
        if file_content.is_a?(Hash)
          filtered_data = filter_ignored_ids(file_content, ignore_ids)
        else
          msg = "file_content #{file_content.inspect} is not a hash"
          bugsnag_notify(msg)
          filtered_data = {}
        end
        combine_arrays = filtered_data.dig('cascade_config', 'combine_arrays') || false
        final_config = MergeUtil.deep_merge(final_config, filtered_data, combine_arrays)
      end

      # Check if any of the values are actually pointing to envars.
      final_config = fetch_envars(final_config)

      # Apply any config filters the user has defined
      final_config = apply_config_filters(final_config)
      # Parse and store configuration.
      @active_scanners = all_none_some(SCANNERS.keys, final_config['active_scanners'])
      @enforced_scanners = all_none_some(SCANNERS.keys, final_config['enforced_scanners'])
      @scanner_configs   = final_config['scanner_configs'] || {}
      @project_name      = final_config['project_name']&.to_s
      @custom_info       = final_config['custom_info']
      @report_uris       = final_config['reports'] || []
      @builds            = final_config['builds'] || {}

      if !valid_name?(@project_name)
        bad_name_msg = "project name #{@project_name} cannot contain spaces, "\
          "square brackets ([]), curly braces ({}) or semicolons (;)"
        raise StandardError, bad_name_msg
      end

      apply_default_scanner_config!
      apply_node_audit_patch!
    end

    # Syntatical sugar to apply salus config filters
    def apply_config_filters(config_hash)
      Salus::PluginManager.apply_filter(:salus_config, :filter_config, config_hash)
    end

    # Syntatical sugar register salus_config filters
    def self.register_filter(filter)
      Salus::PluginManager.register_filter(:salus_config, filter)
    end

    def valid_name?(name)
      return true if name.nil?

      name.count("\s;").zero?
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

    def filter_ignored_ids(config_data, ignore_ids)
      ignore_ids.each do |ignore_id| # Ex. reports:uri_1
        info = ignore_id.split(':')
        key = info[0] # "reports" in "reports:uri_1"
        id = info[1]  # "uri_1" in "reports:uri_1"
        if config_data[key]&.is_a?(Array)
          config_data[key].each do |data|
            config_data[key].delete(data) if data.is_a?(Hash) && data["id"] == id
          end
        end
      end

      config_data
    end

    def apply_node_audit_patch!
      # To allow for backwards compatability and easy switching between node package managers,
      # We will remap any NPMAudit and YarnAudit scanner connfigs to NodeAudit.
      return if %w[NodeAudit NPMAudit YarnAudit].map { |k| @scanner_configs.key?(k) }.none?

      # Make a fully merged config hash for NodeAudit.
      @scanner_configs['NodeAudit'] ||= {}

      @scanner_configs['NodeAudit'] = MergeUtil.deep_merge(@scanner_configs['NodeAudit'],
                                                           @scanner_configs['NPMAudit'], true)
      @scanner_configs['NodeAudit'] = MergeUtil.deep_merge(@scanner_configs['NodeAudit'],
                                                           @scanner_configs['YarnAudit'], true)

      # Copy over the config to the relevant scanners to ensure they all inherit it.
      @scanner_configs['NPMAudit'] = @scanner_configs['NodeAudit']
      @scanner_configs['YarnAudit'] = @scanner_configs['NodeAudit']
    end

    # Applies default scanner config for anything not already defined.
    def apply_default_scanner_config!
      SCANNERS.each_key do |scanner|
        @scanner_configs[scanner] ||= {}
        if @scanner_configs[scanner].is_a? Array
          bugsnag_notify("@scanner_configs[scanner] is Array: #{@scanner_configs[scanner].inspect}")
        end
        @scanner_configs[scanner] = MergeUtil.deep_merge(DEFAULT_SCANNER_CONFIG,
                                                         @scanner_configs[scanner])
      end
    end

    def fetch_envars(config_hash)
      return config_hash if ENV['RUNNING_SALUS_TESTS']

      # Get the configuration back into string format
      config_string = YAML.dump(config_hash)

      # Check for references to envars.
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
