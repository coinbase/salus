def remove_file(file_path)
  File.delete(file_path) if File.exist?(file_path)
end

def version_valid?(version)
  !/^\d+\.\d+(.\d+)*$/.match(version).nil?
end
