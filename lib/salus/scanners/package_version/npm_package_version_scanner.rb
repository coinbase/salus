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

    def check_for_violations(package_name, min_version, max_version)
      if @dependencies.key?(package_name)
        # repo_version: version used in the project
        repo_version = SemVersion.new(@dependencies[package_name].keys[0])
        if repo_version && repo_version < min_version
          line_number = @dependencies[package_name][repo_version.to_s].to_s
          error_msg = "Package version for (#{package_name}) (#{repo_version})" \
          "is less than minimum configured version (#{min_version}) on line " \
          "{#{line_number}} in package-lock.json"
          report_error(error_msg)
          @passed = false
        end

        if repo_version && repo_version > max_version
          line_number = @dependencies[package_name][repo_version.to_s].to_s
          error_msg = "Package version for (#{package_name}) (#{repo_version}) " \
          "is greater than maximum configured version (#{max_version}) on line "\
          "{#{line_number}} in package-lock.json"
          report_error(error_msg)
          @passed = false
        end
      else
        # dependency not present in project
        error_msg = "Package #{package_name} was not found in the package-lock.json"
        report_error(error_msg)
      end
    end

    private

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
