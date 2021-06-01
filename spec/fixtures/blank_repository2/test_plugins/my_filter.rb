module Filter
  module MyCustomConfig
    def self.filter_config(config_hash)
      config_hash['builds'] ||= {}
      config_hash['builds']['abc'] = 'xyz'
      config_hash
    end
  end
end

Salus::Config.register_filter(Filter::MyCustomConfig)
