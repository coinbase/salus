module Salus
  class PluginManager
    PLUGIN_DIRECTORY = 'plugins'.freeze

    def self.plugin_dir
      project_dir = File.expand_path('../salus/', __dir__)
      File.join(project_dir, PLUGIN_DIRECTORY)
    end

    def self.load_plugins
      return if !Dir.exist?(plugin_dir)

      Dir.entries(plugin_dir).sort.each do |filename| # load like how scanners are loaded
        next if ['.', '..'].include?(filename) # don't include FS pointers
        next unless /\.rb\z/.match?(filename)  # only include ruby files

        require "#{plugin_dir}/#{filename}"
      end
    end
  end
end
