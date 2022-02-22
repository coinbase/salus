require_relative '../../../spec_helper'
require_relative 'language_version_scanner_sarif_spec'

describe Sarif::RubyVersionScannerSarif do
  valid_version_repo_path = 'spec/fixtures/language_version/'\
                          'ruby_version_scanner/valid_version'

  invalid_version_repo_path = 'spec/fixtures/language_version/'\
                      'ruby_version_scanner/invalid_version_1'

  error_msg = 'Repository language version (2.1.0) is less '\
                 'than minimum configured version (2.6.0)'

  it_behaves_like "language version scanner sarif",
                  Salus::Scanners::LanguageVersion::RubyVersionScanner,
                  'RubyVersionScanner',
                  valid_version_repo_path,
                  invalid_version_repo_path,
                  error_msg
end
