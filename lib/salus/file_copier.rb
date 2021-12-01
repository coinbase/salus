require 'fileutils'

module Salus
  ##
  # This class is a utility class that can be used to copy files
  # in a temporal fashion.  Directory copies are not yet supported.

  class FileCopier
    ##
    # 
    #

    def copy_files(basedir, destdir, files)
      return yield [] if files.empty?

      copied = []
      # We want to copy each file into our directory
      files.each do |file|
        source = File.join(basedir, file)
        dest = File.join(destdir, file)
        next if !File.exist?(source) || File.exist?(dest) || !File.exist?(destdir)

        # Could also File.symlink but that will limit portability
        FileUtils.cp(source, dest)
        copied << dest
      end

      begin
        yield copied
      ensure
        copied.each do |file|
          File.delete(file)
        end
      end
    end
  end
end
