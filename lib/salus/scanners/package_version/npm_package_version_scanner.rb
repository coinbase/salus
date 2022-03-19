require 'salus/scanners/package_version/base'

module Salus::Scanners::PackageVersion
  class NPMPackageScanner < Base
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
        if repo_version
          line_number = @dependencies[package_name][repo_version.to_s].to_s
          if min_version.present?
            violations.append(
              check_min_version(package_name, line_number, repo_version, min_version)
            )
          end
          if max_version.present?
            violations.append(
              check_max_version(package_name, line_number, repo_version, max_version)
            )
          end
          if blocked_versions.present?
            violations.append(
              check_blocked_versions(package_name, line_number, repo_version, blocked_versions)
            )
          end
        end
      end
      violations.compact
    end

    private

    def check_min_version(package_name, line_number, repo_version, min_version)
      violation = nil
      if repo_version < min_version
        violation = "Package version for (#{package_name}) (#{repo_version}) " \
        "is less than minimum configured version (#{min_version}) on line " \
        "{#{line_number}} in package-lock.json."
      end
      violation
    end

    def check_max_version(package_name, line_number, repo_version, max_version)
      violation = nil
      if repo_version > max_version
        violation = "Package version for (#{package_name}) (#{repo_version}) " \
          "is greater than maximum configured version (#{max_version}) on line "\
          "{#{line_number}} in package-lock.json."
      end
      violation
    end

    def check_blocked_versions(package_name, line_number, repo_version, blocked_versions)
      violation = nil
      blocked_versions.each do |blocked|
        if repo_version == blocked
          violation = "Package version for (#{package_name}) (#{repo_version}) " \
          "matches the configured blocked version (#{blocked}) on line "\
          "{#{line_number}} in package-lock.json."
          break
        end
      end
      violation
    end

    def generate_dependency_hash
      lock_file = "#{@repository.path_to_repo}/package-lock.json"
      # record_dep_locations parses the name, line number and version into a hash
      # {name: {version: line_number}, name: {version: line_number}}
      lock_json = Salus::PackageLockJson.new(lock_file)
      lock_json.record_dep_locations
      lock_json.deps
    end
  end
end
