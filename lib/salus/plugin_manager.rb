module Salus
  class PluginManager
    PLUGIN_DIRECTORY = 'plugins'.freeze
    def self.load_plugins
      project_dir = File.expand_path('../salus/', __dir__)
      dir = File.join(project_dir, PLUGIN_DIRECTORY)
      return if !Dir.exist?(dir)

      Dir.entries(dir).sort.each do |filename| # load like how scanners are loaded
        next if ['.', '..'].include?(filename) # don't include FS pointers
        next unless /\.rb\z/.match?(filename)  # only include ruby files

        require "#{dir}/#{filename}"
      end
    end
  end
end
