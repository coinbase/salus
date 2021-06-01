module Filter
  module MyCustomConfig2
    def self.filter_config(config_hash)
      config_hash['builds'] ||= {}
      config_hash['builds']['abcd'] = 'xyzw'
      config_hash
    end
  end
end

Salus::Config.register_filter(Filter::MyCustomConfig2)
