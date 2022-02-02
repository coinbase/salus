require 'salus/scanners/base'

module Salus::Scanners::PackageVersion
  class Base < Salus::Scanners::Base
    class SemVersion < Gem::Version; end

    def initialize(repository:, config:)
      super
      @passed = true
    end

    def run
      # gather all package versions specified in scanner_config
      package_versions = @config['package_versions']

      # for each package in there, check if any violoations exist
      package_versions.each do |name, specified_version|
        min_version = SemVersion.new(specified_version['min_version'])
        max_version = SemVersion.new(specified_version['max_version'])
        check_for_violations(name, min_version, max_version)
      end

      @passed ? report_success : report_failure
    end

    # Check if a package doesnt fall within a version range
    # calls raise_error if it dosent fall withing the specified range
    def check_for_violations(_package_name, _min_version, _max_version)
      raise NoMethodError
    end

    def name
      self.class.name.sub('Salus::Scanners::PackageVersion::', '')
    end
  end
end
