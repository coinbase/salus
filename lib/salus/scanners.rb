module Salus::Scanners; end

# We'll sort to avoid any race conditions in loading order
Dir.entries(File.expand_path('scanners', __dir__)).sort.each do |filename|
  next if ['.', '..'].include?(filename) # don't include FS pointers
  next unless /\.rb\z/.match?(filename)  # only include ruby files
  require "salus/scanners/#{filename}"
end
