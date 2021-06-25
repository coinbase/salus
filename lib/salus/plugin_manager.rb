module Salus
  class PluginManager
    PLUGIN_DIRECTORY = 'plugins'.freeze
    class << self
      # Salus::Config.register_filter(Filter::MyCustomConfig)
      # Salus::PluginManager.register_filter()

      # Our hashmap of filters
      @@filters = {}
      @@listners = []

      def register_filter(filter_family, filter)
        @@filters[filter_family] ||= []
        @@filters[filter_family] << filter
      end

      def register_listener(listener)
        @@listners << listener
      end

      def apply_filter(filter_family, filter_method, data)
        @@filters[filter_family]&.each do |f|
          data = f.__send__(filter_method, data) if f.respond_to?(filter_method)
        end
        data
      end

      def send_event(event_name, *data)
        @@listners.each do |l|
          l.__send__(event_name, *data) if l.respond_to?(event_name)
        end
      end

      def plugin_dir
        project_dir = File.expand_path('../salus/', __dir__)
        File.join(project_dir, PLUGIN_DIRECTORY)
      end

      @@loaded = Set.new
      def load_plugins
        # We only need to load once
        return if !Dir.exist?(plugin_dir) || @@loaded.include?(plugin_dir)

        @@loaded.add(plugin_dir)

        Dir.entries(plugin_dir).sort.each do |filename| # load like how scanners are loaded
          next if ['.', '..'].include?(filename) # don't include FS pointers
          next unless /\.rb\z/.match?(filename)  # only include ruby files

          require "#{plugin_dir}/#{filename}"
        end
      end
    end
  end
end
