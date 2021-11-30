require 'fileutils'
require 'pry'

module Salus

  ##
  # This class is used to search for directories to run salus against based
  # on the provided configuration

  class FileCopier    
    # Note we support files not directories
    def copy_files(basedir, destdir, files)
      return yield [] if files.empty?  # basedir.nil? || destdir.nil? || files.nil? || 

      copied = []
      # We want to copy each file into our directory
      files.each do |file|
        source = File.join(basedir, file) # "spec/fixtures/processor/recursive"
        dest = File.join(destdir, file) # "spec/fixtures/processor/recursive"
        # Could also File.symlink 
        next if !File.exist?(source) || File.exist?(dest) || !File.exist?(destdir)

        puts "Copy #{source} to #{dest}"
        FileUtils.cp(source, dest)
        #binding.pry
        copied << dest
      end
      copied
      begin
        puts "yielding to client code"
        yield copied
        puts "back from yield"
      ensure
        puts "Cleanup"
        copied.each do |file|
          puts "Delete #{file}"
          File.delete(file)# if File.exist?(file)
        end
      end

    end
  end
end