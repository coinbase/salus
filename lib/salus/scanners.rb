module Salus::Scanners; end

paths = ['scanners', 'scanners/language_version', 'scanners/package_version', 'scanners/osv']
paths.each do |path|
  # Sort to avoid race conditions caused by differing load orders.
  Dir.entries(File.expand_path(path, __dir__)).sort.each do |filename|
    next if ['.', '..'].include?(filename) # don't include FS pointers
    next unless /\.rb\z/.match?(filename)  # only include ruby files

    require "salus/#{path}/#{filename}"
  end
end
