# Usage:  RepoSearcher.new(@repo_path, config).matching_repos.each do |repo|
require 'salus/file_copier'
require 'pry'
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
    def initialize(path_to_repo, scanner_config)
      @path_to_repo = path_to_repo # "spec/fixtures/processor/recursive"
      @scanner_config = scanner_config # {"pass_on_raise"=>false, "scanner_timeout_s"=>0}
    end

    ##
    # List the repos matching the rules defined in the scanner config.
    # If the scanner config lacks any recusion rules for matching directores
    # a single element array will be returned with the +path_to_repo+
    #
    # @return [Salus::Repo]
    #
    def matching_repos
      return yield Repo.new(@path_to_repo) unless recurse?

      dirs = static_directories + dynamic_directories
      # We want to copy over files we need to here and yield back the repo

      filter_out_exlcusions(dirs.uniq).map do |repo|
        # If we have any static files in the config, copy them
        # as needed
        dest_dir =  File.expand_path(repo)
        next unless Dir.exist?(dest_dir)

        FileCopier.new.copy_files(File.expand_path(@path_to_repo), dest_dir, static_files) do
          yield Repo.new(repo)
        end
      end
    end

    def recurse?
      @scanner_config.key?('recursion')
    end

    protected

    def static_directories
      dirs = @scanner_config.dig('recursion', 'directories') || []
      resolve_dirs(dirs)
    end

    def static_files
      @static_files ||= @scanner_config.dig('recursion', 'static_files') || []
      @static_files
    end

    def dynamic_directories
      matching_rules = @scanner_config.dig('recursion', 'directories_matching') || []
      # Let's search for any dirs matching these rules
      directories_matching(matching_rules)
    end

    def filter_out_exlcusions(dirs)
      return [] if dirs.nil?

      exclusions = @scanner_config.dig('recursion', 'directory_exclusions') || []
      exclusions.map! { |dir| File.join(@path_to_repo.to_s, dir) }
      return dirs if dirs.empty? || exclusions.empty?

      dirs.select { |dir| !dir.start_with?(*exclusions) }
    end

    def search_files_named(filename)
      #  rg --files | rg package.json
      cmd = "rg --files | rg #{filename}"
      run_rg(cmd)
    end

    def search_files_named_containing(filename, content)
      # RUNNING rg --files-with-matches activesupport Gemfile.lock
      cmd = "rg --files-with-matches #{content} --glob #{filename}"
      run_rg(cmd)
    end

    def search_files_containing(content)
      #  rg -l foo
      cmd = "rg -l #{content}"
      run_rg(cmd)
    end

    def run_rg(command)
      puts "RUNNING #{command}"
      data = nil
      Dir.chdir(@path_to_repo) do
        data = `#{command}`
      end
      return [] if data == ""

      files = data.lines.map(&:strip)
      # files are all relative to @path_to_repo
      files
    end

    def parent_dirs(files)
      dirs = files.map { |file| Pathname.new(file)&.parent&.to_s }
      dirs.uniq
    end

    def matches_from_rule(rule)
      filename = rule['filename']
      content = rule['content']
      files = []
      if !filename.nil? && !content.nil?
        files = search_files_named_containing(filename, content)
      elsif filename.present?
        files = search_files_named(filename)
      elsif !content.empty?
        files = search_files_containing(content)
      end
      parent_dirs(files)
    end

    def directories_matching(rules)
      dirs = Set.new
      rules.each do |rule|
        dirs.merge(matches_from_rule(rule))
      end
      #  [".", "project-two"]
      resolve_dirs(dirs.to_a)
    end

    def resolve_dirs(dirs)
      dirs.map { |dir| Pathname(@path_to_repo).join(dir).to_s }
    end
  end
end
