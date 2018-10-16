module Salus::Scanners; end

Dir.entries('lib/salus/scanners').each do |scanner_file|
  next if ['.', '..'].include?(scanner_file) # don't include FS pointers
  next unless /\.rb\z/.match?(scanner_file)  # only include ruby files

  require "salus/scanners/#{scanner_file}"
end
