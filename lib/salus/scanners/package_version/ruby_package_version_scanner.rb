require 'salus/scanners/package_version/base'

module Salus::Scanners::PackageVersion
  class RubyPackageScanner < Base
    LOCK_FILE = "Gemfile.lock".freeze
    def initialize(repository:, config:)
      super
      @dependencies = should_run? ? generate_dependency_hash : {}
    end

    def should_run?
      @repository.gemfile_lock_present?
    end

    def self.supported_languages
      ['ruby']
    end

    def check_for_violations(package_name, min_version, max_version, blocked_versions)
      violations = []
      if @dependencies.key?(package_name)
        # repo_version: version used in the project
        repo_version = SemVersion.new(@dependencies[package_name])
        if repo_version
          violations += [
            if compare_semver_version(MIN_CHECK, repo_version, min_version)
              format_min_violation_message(package_name: package_name,
                package_version: repo_version, version: min_version,
                file: LOCK_FILE)
            end,
            if compare_semver_version(MAX_CHECK, repo_version, max_version)
              format_max_violation_message(package_name: package_name,
                package_version: repo_version, version: max_version,
                file: LOCK_FILE)
            end,
            if compare_semver_version(BLOCK_CHECK, repo_version, blocked_versions)
              format_blocked_violation_message(package_name: package_name,
                package_version: repo_version, version: blocked_versions,
                file: LOCK_FILE)
            end
          ]
        end
      end
      violations.compact
    end

    private

    def generate_dependency_hash
      deps = {}
      lockfile = Bundler::LockfileParser.new(@repository.gemfile_lock)
      lockfile.specs.each do |gem|
        deps[gem.name] = gem.version.to_s
      end
      deps
    end
  end
end
