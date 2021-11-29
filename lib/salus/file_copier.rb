require 'fileutils'
require 'pry'
module Salus

  ##
  # This class is used to search for directories to run salus against based
  # on the provided configuration

  class FileCopier    

    def copy_files(basedir, destdir, files)
      return if files.empty?
      copied = []
      # We want to copy each file into our directory
      files.each do |file|
        source = File.join(basedir, file) # "spec/fixtures/processor/recursive"
        dest = File.join(destdir, file) # "spec/fixtures/processor/recursive"
        # Could also File.symlink 
        next if !File.exist?(source) || File.exist?(dest) || !File.exist?(destdir)

        puts "Copy #{source} to #{dest}"

        FileUtils.cp(source, dest)
        copied << dest
      end
      copied
      yield
      copied.each do |file|
        puts "Delete #{file}"
        FileUtils.delete(file)
      end
    end
  end
end