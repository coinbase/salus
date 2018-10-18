module Salus::Scanners; end

Dir.entries(File.expand_path('scanners', __dir__)).each do |filename|
  next if ['.', '..'].include?(filename) # don't include FS pointers
  next unless /\.rb\z/.match?(filename)  # only include ruby files
  require_relative "scanners/#{filename}"
end
