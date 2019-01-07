module Salus
  class Repo
    attr_reader :path_to_repo

    IMPORTANT_FILES = [
      # Ruby
      { handle: :gemfile, filename: 'Gemfile' },
      { handle: :gemfile_lock, filename: 'Gemfile.lock' },
      # JS
      { handle: :package_json, filename: 'package.json' },
      { handle: :package_lock_json, filename: 'package-lock.json' },
      { handle: :yarn_lock, filename: 'yarn.lock' },
      { handle: :npmrc, filename: '.npmrc' },
      # Go
      { handle: :dep_lock, filename: 'Gopkg.lock' },
      { handle: :go_mod, filename: 'go.mod' },
      { handle: :go_sum, filename: 'go.sum' },
      # Python
      { handle: :requirements_txt, filename: 'requirements.txt' }
    ].freeze

    # Define file checkers.
    IMPORTANT_FILES.each do |file|
      define_method :"#{file[:handle]}_present?" do
        File.exist?("#{@path_to_repo}/#{file[:filename]}")
      end
    end

    # Define cached file getters.
    IMPORTANT_FILES.each do |file|
      define_method file[:handle] do
        cache_handle = "@#{file[:handle]}_contents"

        if File.exist?("#{@path_to_repo}/#{file[:filename]}")
          if instance_variable_get(cache_handle).nil?
            instance_variable_set(cache_handle, File.read("#{@path_to_repo}/#{file[:filename]}"))
          end
        end

        instance_variable_get(cache_handle)
      end
    end

    def initialize(path_to_repo = nil)
      @path_to_repo = path_to_repo
    end
  end
end
