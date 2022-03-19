require 'salus/scanners/package_version/base'

module Salus::Scanners::PackageVersion
  class GoPackageScanner < Base
    LOCK_FILE = "go.sum".freeze
    def initialize(repository:, config:)
      super
      @dependencies = should_run? ? generate_dependency_hash : {}
    end

    def should_run?
      @repository.go_sum_present?
    end

    def check_for_violations(package_name, min_version, max_version, blocked_versions)
      violations = []
      if @dependencies.key?(package_name)
        # repo_version: version used in the project
        repo_version = SemVersion.new(@dependencies[package_name])
        if repo_version
          violations.append(
            if compare_semver_version("MINIMUM_VERSION_CHECK", repo_version, min_version)
              "Package version for (#{package_name}) (#{repo_version}) " \
              "is less than minimum configured version (#{min_version}) in #{LOCK_FILE}."
            end
          )
          violations.append(
            if compare_semver_version("MAXIMUM_VERSION_CHECK", repo_version, max_version)
              "Package version for (#{package_name}) (#{repo_version}) " \
              "is greater than maximum configured version (#{max_version}) in #{LOCK_FILE}."
            end
          )
          violations.append(
            if compare_semver_version("BLOCKED_VERSION_CHECK", repo_version, blocked_versions)
              "Package version for (#{package_name}) (#{repo_version}) " \
              "matches the configured blocked version in #{LOCK_FILE}."
            end
          )
        end
      end
      violations.compact
    end

    private

    def generate_dependency_hash
      parser = Salus::GoDependencyParser.new(@repository.go_sum_path)
      parser.parse
      dependencies = parser.select_dependencies(parser.go_dependencies)
      dependencies
    end
  end
end
