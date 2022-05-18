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

    def self.supported_languages
      ['javascript']
    end

    def check_for_violations(package_name, min_version, max_version, blocked_versions)
      violations = []
      if @dependencies.key?(package_name)
        # repo_version: version used in the project
        repo_version = SemVersion.new(@dependencies[package_name].keys[0])
        line_number = @dependencies[package_name][repo_version.to_s].to_s
        if repo_version
          violations += [
            if compare_semver_version(MIN_CHECK, repo_version, min_version)
              format_min_violation_message(package_name: package_name,
                package_version: repo_version, version: min_version,
                file: LOCK_FILE, line: line_number)
            end,
            if compare_semver_version(MAX_CHECK, repo_version, max_version)
              format_max_violation_message(package_name: package_name,
                package_version: repo_version, version: max_version,
                file: LOCK_FILE, line: line_number)
            end,
            if compare_semver_version(BLOCK_CHECK, repo_version, blocked_versions)
              format_blocked_violation_message(package_name: package_name,
                package_version: repo_version, version: blocked_versions,
                file: LOCK_FILE, line: line_number)
            end
          ]
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
