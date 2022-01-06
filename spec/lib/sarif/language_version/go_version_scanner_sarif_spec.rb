require_relative '../../../spec_helper'
require_relative 'language_version_scanner_sarif_spec'

describe Sarif::GoVersionScannerSarif do
  valid_version_repo_path = 'spec/fixtures/language_version/'\
                          'go_version_scanner/valid_version'

  invalid_version_repo_path = 'spec/fixtures/language_version/'\
                      'go_version_scanner/invalid_version_1'

  error_msg = 'Repository language version (1.14) is less '\
                 'than minimum configured version (1.15.0)'

  it_behaves_like "language version scanner sarif",
                  Salus::Scanners::LanguageVersion::GoVersionScanner,
                  'GoVersionScanner',
                  valid_version_repo_path,
                  invalid_version_repo_path,
                  error_msg
end
