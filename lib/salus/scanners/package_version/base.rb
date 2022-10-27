require 'salus/scanners/base'

module Salus::Scanners::PackageVersion
  class Base < Salus::Scanners::Base
    class SemVersion < Gem::Version; end

    MIN_CHECK = "MINIMUM_VERSION_CHECK".freeze
    MAX_CHECK = "MAXIMUM_VERSION_CHECK".freeze
    BLOCK_CHECK = "BLOCKED_VERSION_CHECK".freeze

    def initialize(repository:, config:)
      super
    end

    def self.scanner_type
      Salus::ScannerTypes::DEPENDENCY
    end

    def run
      # gather all package versions specified in scanner_config
      package_versions = @config['package_versions'] || []
      results = []
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
          results.concat check_for_violations(name, min_version, max_version, blocked_versions)
        end
      rescue ArgumentError
        err_msg = "Malformed SEMVER version number found."
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end
      return report_success if results.empty?

      report_failure
      log(JSON.pretty_generate(results))
    end

    # Check if a package doesnt fall within a version range
    # calls raise_error if it dosent fall withing the specified range
    def check_for_violations(_package_name, _min_version, _max_version, _blocked_versions)
      raise NoMethodError
    end

    def name
      self.class.name.sub('Salus::Scanners::PackageVersion::', '')
    end

    def self.supported_languages
      []
    end

    private

    def parse_blocked_versions(blocked_versions)
      versions = []
      blocked_versions.split(",").each do |blocked_version|
        versions.append(SemVersion.new(blocked_version.strip))
      end
      versions
    end

    def compare_semver_version(type, dependency_version, version_configured)
      if version_configured.present?
        case type
        when MIN_CHECK then dependency_version < version_configured
        when MAX_CHECK then dependency_version > version_configured
        when BLOCK_CHECK then version_configured.include? dependency_version
        else false
        end
      end
    end

    def format_min_violation_message(package_name:, package_version:, version:, file:, line: nil)
      if line.present?
        "Package version for (#{package_name}) (#{package_version}) is less than minimum " \
        "configured version (#{version}) on line {#{line}} in #{file}."
      else
        "Package version for (#{package_name}) (#{package_version}) is less than minimum " \
        "configured version (#{version}) in #{file}."
      end
    end

    def format_max_violation_message(package_name:, package_version:, version:, file:, line: nil)
      if line.present?
        "Package version for (#{package_name}) (#{package_version}) is greater than " \
        "maximum configured version (#{version}) on line {#{line}} in #{file}."
      else
        "Package version for (#{package_name}) (#{package_version}) is greater than " \
        "maximum configured version (#{version}) in #{file}."
      end
    end

    def format_blocked_violation_message(package_name:, package_version:, version:, file:,
                                         line: nil)
      version = version.map(&:to_s).join(",")
      if line.present?
        "Package version for (#{package_name}) (#{package_version}) matches " \
        "the configured blocked version (#{version}) on line {#{line}} "\
        "in #{file}."
      else
        "Package version for (#{package_name}) (#{package_version}) matches " \
        "the configured blocked version (#{version}) in #{file}."
      end
    end
  end
end
