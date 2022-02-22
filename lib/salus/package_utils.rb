Dir.entries(File.expand_path('package_utils', __dir__)).sort.each do |filename|
  next if ['.', '..'].include?(filename) # don't include FS pointers
  next unless /\.rb\z/.match?(filename)  # only include ruby files

  require "salus/package_utils/#{filename}"
end
