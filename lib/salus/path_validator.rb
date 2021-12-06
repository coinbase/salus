module Salus
  class PathValidator
    def initialize(base_path)
      @base_path = base_path
    end

    def local_to_base?(path)
      return true if @base_path.nil?

      path = Pathname.new(File.expand_path(path)).cleanpath.to_s
      rpath = File.expand_path(@base_path)
      return true if path == rpath
      if !path.start_with?(rpath + "/") || path.include?("/.")
        # the 2nd condition covers like abcd/.hidden_file or abcd/..filename
        # which cleanpath does not do anything about
        return false
      end

      true
    end
  end
end
