require 'fileutils'

module Salus
  ##
  # This class is a utility class that can be used to copy files
  # in a temporal fashion.  Directory copies are not yet supported.

  class FileCopier
    # copy_files is used to temporarily copy files before automatically
    # cleaning up the copied files.  The method will yield the list of files that
    # were found and copied and upon completion remove the copied files to keep
    # the function impotent in regards to the filesystem.
    #
    # @param [String] basedir The path to the base directory containing the files to copy.
    # @param [String] destir The path to destination directory where the files will
    # copied to.
    # @param [Array] files An array of strings listing the filenames to copy

    def initialize(auto_cleanup: true)
      @auto_cleanup = auto_cleanup
    end

    def copy_files(basedir, destdir, files)
      if files.empty?
        yield []
        return []
      end

      copied = []
      # We want to copy each file into our directory
      files.each do |file|
        source = File.join(basedir, file)
        dest = File.join(destdir, file)
        # No need to process this entry if we can't find it
        next if !File.exist?(source) || File.exist?(dest) || !File.exist?(destdir)

        # Could also File.symlink but that will limit portability so we're
        # just copying the file instead
        FileUtils.cp(source, dest)
        copied << dest
      end

      begin
        yield copied
      ensure
        copied.each do |file|
          File.delete(file) if @auto_cleanup
        end
      end
      copied
    end
  end
end
