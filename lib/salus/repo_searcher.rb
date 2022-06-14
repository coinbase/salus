# Usage:  RepoSearcher.new(@repo_path, config).matching_repos.each do |repo|
require 'salus/file_copier'

module Salus
  ##
  # This class is used to search for directories to run salus against based
  # on the provided configuration

  class RepoSearcher
    attr_reader :path_to_repo, :scanner_config

    ##
    # Creates a new repo searched for the passed +directory+ and +scanner config+.
    #
    # @param [String] path_to_repo The path to the directory to scan.
    # @param [Hash] scanner_config The settings for this scanner (from salus.yaml).
    #
    def initialize(path_to_repo, scanner_config, auto_cleanup = true)
      @path_to_repo = path_to_repo # "spec/fixtures/processor/recursive"
      @scanner_config = scanner_config # {"pass_on_raise"=>false, "scanner_timeout_s"=>0}
      @auto_cleanup = auto_cleanup
    end

    ##
    # List the repos matching the rules defined in the scanner config.
    # If the scanner config lacks any recusion rules for matching directores
    # a single element array will be returned with the +path_to_repo+
    #
    # @return [Salus::Repo]
    #
    def matching_repos
      files_copied = []
      unless recurse?
        yield Repo.new(@path_to_repo)
        return files_copied
      end

      # Ensure we only scan directories that are descendants of @path_to_repo
      dirs = filter_safe_repos(static_directories + dynamic_directories)

      # We want to copy over files we need to here and yield back the repo
      filter_out_exlcusions(dirs.uniq).map do |repo|
        # If we have any static files in the config, copy them
        # as needed
        dest_dir =  File.expand_path(repo)

        next unless Dir.exist?(dest_dir)

        copied = FileCopier.new(auto_cleanup: @auto_cleanup)
          .copy_files(File.expand_path(@path_to_repo), dest_dir, static_files) do
          yield Repo.new(repo)
        end
        files_copied.concat(copied) unless copied.empty?
      end
      files_copied&.uniq
    end

    ##
    # @param [Array] args CLI rg command and options to run
    # @return [Array<String>] Relative path of files returned
    # from running the command.
    def run_rg(*args)
      data = IO.popen(args, chdir: @path_to_repo).read
      return [] if data == ""

      files = data.lines.map(&:strip)
      # files are all relative to @path_to_repo
      files
    end

    protected

    ##
    # @return [boolean] True if the scanner config has a recusion entry
    #
    def recurse?
      @scanner_config.key?('recursion')
    end

    ##
    # @return [Array<String>] List of directories from the recusion.directories
    # configuration prefixed to be relative to @path_to_repo
    #
    def static_directories
      dirs = @scanner_config.dig('recursion', 'directories') || []
      resolve_dirs(dirs)
    end

    ##
    # @return [Array<String>] List of static files from the recursion.static_files
    # configuration
    def static_files
      @static_files ||= @scanner_config.dig('recursion', 'static_files') || []
      @static_files
    end

    ##
    # @return [Array<String>] List of directories that match the rules defined
    # in recusion.directories_matching after searching. Prefixed to be relative
    # to @path_to_repo
    def dynamic_directories
      matching_rules = @scanner_config.dig('recursion', 'directories_matching') || []
      # Let's search for any dirs matching these rules
      directories_matching(matching_rules)
    end

    ##
    # @param [Array<String>] dirs List of directories
    # @return [Array<String>] Filtered set of directories after removing
    # directories that start with any directories listed in the
    # recursion.directory_exclusions configuration
    def filter_out_exlcusions(dirs)
      return [] if dirs.nil?

      exclusions = @scanner_config.dig('recursion', 'directory_exclusions') || []
      exclusions.map! { |dir| File.join(@path_to_repo.to_s, dir) }
      return dirs if dirs.empty? || exclusions.empty?

      dirs.reject { |dir| dir.start_with?(*exclusions) }
    end

    ##
    # The method will raise if any params are found to not be subdirectories
    # of repo_path.  This is to match the behavior in Salus::Report that raises
    # on the presense of directory references outside the repo directory
    # @param [Array<String>] List of directories to validate
    # @return [Array<String>] List of directories that are subdirectores of repo_apth
    def filter_safe_repos(dirs)
      validator = Salus::PathValidator.new(@path_to_repo)
      valid_dirs, invalid = dirs.partition { |dir| validator.local_to_base?(dir) }

      raise "Directory #{invalid.first} must be local to repo path" unless invalid.empty?

      valid_dirs
    end

    ##
    # @param [String] filename Filename to search for.
    # @return [Array<String>] List of files found to have the passed
    # filename.  Recusive search from @path_to_repo is preformed to find
    # the mathces
    def search_files_named(filename)
      run_rg("rg", "--files", "-g", filename)
    end

    ##
    # @param [String] filename Filename to search for.
    # @param [String] content File content to search for.
    # @return [Array<String>] List of files found to contain the passed
    # content and matching the provided filename.  Recusive search from
    # @path_to_repo is preformed to find the mathces
    def search_files_named_containing(filename, content)
      run_rg("rg", "--files-with-matches", content, "--glob", filename)
    end

    ##
    # @param [String] content File content to search for.
    # @return [Array<String>] List of files found to contain the passed
    # content.  Recusive search from @path_to_repo is preformed to find
    # the mathces
    def search_files_containing(content)
      run_rg("rg", "-l", content)
    end

    ##
    # @param [Array<String>] files List of files to determine parent
    # directories for.
    # @return [Array<String>] Parent directories from input list of
    # files.  The directoires are returned relative to @path_to_repo
    # and duplicates are removed.
    # Example:
    # Input: ["vendor/Gemfile.lock", "Gemfile.lock", "project-two/Gemfile.lock"]
    # Returns: ["vendor", ".", "project-two"]
    def parent_dirs(files)
      dirs = files.map { |file| Pathname.new(file)&.parent&.to_s }
      dirs.uniq
    end

    ##
    # @param [Hash] rule Hash containing filename and/or content keys
    # @return [Array<String>] List of directories containing files that
    # match the rules defined after searching.
    def matches_from_rule(rule)
      filename = rule['filename']
      content = rule['content']
      files = []

      if filename.present? && content.present?
        files = search_files_named_containing(filename, content)
      elsif filename.present?
        files = search_files_named(filename)
      elsif content.present?
        files = search_files_containing(content)
      end
      parent_dirs(files)
    end

    ##
    # @param [Array<Hash>] rules Arraay of hashes containing filename and/or
    # content keys
    # @return [Array<String>] List of directories containing files that
    # match the rules defined after searching. Prefixed to be relative
    # to @path_to_repo
    def directories_matching(rules)
      dirs = Set.new
      rules.each do |rule|
        dirs.merge(matches_from_rule(rule))
      end
      #  [".", "project-two"]
      resolve_dirs(dirs.to_a)
    end

    ##
    # @param [Array<String>] dirs Arraay of relative directory names
    # @return [Array<String>] List of directories prefixed to be relative
    # to @path_to_repo
    # Example:
    # Input: ["foo"]
    # Output: ["spec/fixtures/processor/recursive/foo"]
    def resolve_dirs(dirs)
      dirs.map { |dir| Pathname(@path_to_repo).join(dir).to_s }
    end
  end
end
