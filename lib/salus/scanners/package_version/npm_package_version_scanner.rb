require 'salus/scanners/package_version/base'

module Salus::Scanners::PackageVersion
  class NPMPackageScanner < Base
    LOCK_FILE = "package-lock.json".freeze
    def initialize(repository:, config:)
      super
      @dependencies = should_run? ? generate_dependency_hash : {}
    end

    def should_run?
      @repository.package_lock_json_present?
    end

    def check_for_violations(package_name, min_version, max_version, blocked_versions)
      violations = []
      if @dependencies.key?(package_name)
        # repo_version: version used in the project
        repo_version = SemVersion.new(@dependencies[package_name].keys[0])
        line_number = @dependencies[package_name][repo_version.to_s].to_s
        if repo_version
          violations.append(
            if compare_semver_version("MINIMUM_VERSION_CHECK", repo_version, min_version)
              "Package version for (#{package_name}) (#{repo_version}) " \
              "is less than minimum configured version (#{min_version}) on line " \
              "{#{line_number}} in #{LOCK_FILE}."
            end
          )
          violations.append(
            if compare_semver_version("MAXIMUM_VERSION_CHECK", repo_version, max_version)
              "Package version for (#{package_name}) (#{repo_version}) " \
              "is greater than maximum configured version (#{max_version}) on line " \
              "{#{line_number}} in #{LOCK_FILE}."
            end
          )
          violations.append(
            if compare_semver_version("BLOCKED_VERSION_CHECK", repo_version, blocked_versions)
              "Package version for (#{package_name}) (#{repo_version}) " \
              "matches the configured blocked version on line " \
              "{#{line_number}} in #{LOCK_FILE}."
            end
          )
        end
      end
      violations.compact
    end

    private

    def generate_dependency_hash
      lock_file = "#{@repository.path_to_repo}/#{LOCK_FILE}"
      # record_dep_locations parses the name, line number and version into a hash
      # {name: {version: line_number}, name: {version: line_number}}
      lock_json = Salus::PackageLockJson.new(lock_file)
      lock_json.record_dep_locations
      lock_json.deps
    end
  end
end
