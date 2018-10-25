require 'toml'
require 'salus/scanners/base'

# Report the use of Go packages captured in a Gopkg.lock files.
# https://github.com/golang/dep

module Salus::Scanners
  class ReportGoDep < Base
    def run
      unless should_run?
        raise(
          InvalidScannerInvocationError,
          'Cannot report on Go dependencies without a Gopkg.lock file.'
        )
      end
      dep_lock = TOML::Parser.new(@repository.dep_lock).parsed

      # Report dependencies
      dep_lock['projects'].each do |dependency|
        record_dep_package(
          name: dependency['name'],
          reference: dependency['revision'],
          version_tag: dependency['version']
        )
      end
    end

    def should_run?
      @repository.dep_lock_present?
    end

    private

    def record_dep_package(name:, reference:, version_tag:)
      report_dependency(
        'Gopkg.lock',
        type: 'go_dep_lock',
        name: name,
        reference: reference,
        version_tag: version_tag
      )
    end
  end
end
