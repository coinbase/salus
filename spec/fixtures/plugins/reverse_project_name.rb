# Sample Config Filter Plugin
# This filter simple reverse the supplied project_name before the config is applied

module Filter
  module ReverseProjectName
    def self.filter_config(config_hash)
      config_hash['project_name'] ||= ''
      config_hash['project_name'].reverse!
      config_hash
    end
  end
end

Salus::Config.register_filter(Filter::ReverseProjectName)
