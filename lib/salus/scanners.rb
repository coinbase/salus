module Salus::Scanners; end

# Sort to avoid race conditions caused by differing load orders.
Dir.entries(File.expand_path('scanners', __dir__)).sort.each do |filename|
  next if ['.', '..'].include?(filename) # don't include FS pointers
  next unless /\.rb\z/.match?(filename)  # only include ruby files

  require "salus/scanners/#{filename}"
end

Dir.entries(File.expand_path('scanners/language_version', __dir__)).sort.each do |filename|
  next if ['.', '..'].include?(filename) # don't include FS pointers
  next unless /\.rb\z/.match?(filename)  # only include ruby files

  require "salus/scanners/language_version/#{filename}"
end


Dir.entries(File.expand_path('scanners/github_advisory', __dir__)).sort.each do |filename|
  next if ['.', '..'].include?(filename) # don't include FS pointers
  next unless /\.rb\z/.match?(filename)  # only include ruby files

  require "salus/scanners/github_advisory/#{filename}"
end
