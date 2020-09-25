module Salus
  class PluginManager
    DEFAULT_DIRECTORY = 'plugins'.freeze

    def self.load_plugins(directory = nil)
      directory ||= DEFAULT_DIRECTORY
      # Note we should add zeitwerk to salus and clean up how we do require's
      # in salus. Short of that, we probably should memoize this per directory
      # passed
      project_dir = File.expand_path('../../', __dir__)
      search = File.expand_path(File.join(directory, '*.rb'), project_dir)

      Dir[search].sort.each do |filename|
        require filename
      end
    end
  end
end
