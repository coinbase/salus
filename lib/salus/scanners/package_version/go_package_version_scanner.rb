require 'salus/scanners/package_version/base'

module Salus::Scanners::PackageVersion
  class GoPackageScanner < Base
    def initialize(repository:, config:)
      super
      @dependencies = should_run? ? generate_dependency_hash : {}
    end

    def should_run?
      @repository.go_sum_present?
    end

    def check_for_violations(package_name, min_version, max_version, blocked_versions)
      if @dependencies.key?(package_name)
        # repo_version: version used in the project
        repo_version = SemVersion.new(@dependencies[package_name])

        if repo_version
          check_min_version(package_name, repo_version, min_version) if min_version.present?
          check_max_version(package_name, repo_version, max_version) if max_version.present?
          if blocked_versions.present?
            check_blocked_versions(package_name, repo_version, blocked_versions)
          end
        end
      end
    end

    private

    def check_min_version(package_name, repo_version, min_version)
      if repo_version < min_version
        msg = "Package version for (#{package_name}) (#{repo_version})" \
        " is less than minimum configured version (#{min_version}) in go.sum"
        report_error_status(msg)
      end
    end

    def check_max_version(package_name, repo_version, max_version)
      if repo_version > max_version
        msg = "Package version for (#{package_name}) (#{repo_version})" \
          " is greater than maximum configured version (#{max_version}) in go.sum"
        report_error_status(msg)
      end
    end

    def check_blocked_versions(package_name, repo_version, blocked_versions)
      blocked_versions.each do |blocked|
        if repo_version == blocked
          msg = "Package version for (#{package_name}) (#{repo_version})" \
          " matches the configured blocked version (#{blocked}) in go.sum"
          report_error_status(msg)
        end
      end
    end

    def generate_dependency_hash
      parser = Salus::GoDependencyParser.new(@repository.go_sum_path)
      parser.parse
      dependencies = parser.select_dependencies(parser.go_dependencies)
      dependencies
    end
  end
end
