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
      package_versions = @config['package_versions'] || []

      begin
        # for each package in there, check if any violations exist
        package_versions.each do |name, specified_version|
          min_version = if specified_version['min_version'].present?
                          SemVersion.new(specified_version['min_version'])
                        end
          max_version = if specified_version['max_version'].present?
                          SemVersion.new(specified_version['max_version'])
                        end
          blocked_versions = if specified_version['block'].present?
                               parse_blocked_versions(specified_version['block'])
                             end
          check_for_violations(name, min_version, max_version, blocked_versions)
        end
      rescue ArgumentError
        err_msg = "Malformed SEMVER version number found."
        report_stderr(err_msg)
        report_error(err_msg)
        return
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

    private

    def parse_blocked_versions(blocked_versions)
      versions = []
      blocked_versions.split(",").each do |blocked_version|
        versions.append(SemVersion.new(blocked_version.strip))
      end
      versions
    end
  end
end
