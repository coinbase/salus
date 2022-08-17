require 'salus/yarn_formatter'
require 'salus/autofixers/base'

module Salus::Autofixers
  class YarnAuditV2 < Base
    def initialize(path_to_repo)
      @path_to_repo = path_to_repo
    end

    # Auto Fix will try to attempt direct and indirect dependencies
    # Direct dependencies are found in package.json
    # Indirect dependencies are found in yarn.lock
    # By default, it will skip major version bumps
    def run_auto_fix(feed, path_to_repo, package_json, yarn_lock)
      fix_indirect_dependency(feed, yarn_lock, path_to_repo)
      fix_direct_dependency(feed, package_json, path_to_repo)
    rescue StandardError => e
      error_msg = "An error occurred while auto-fixing vulnerabilities: #{e}, #{e.backtrace}"
      raise AutofixError, error_msg
    end

    def fix_direct_dependency(feed, package_json, path_to_repo)
      packages = JSON.parse(package_json)
      feed.each do |vuln|
        patch = vuln[:target]
        resolves = vuln[:resolves]
        package = vuln[:module]
        resolves.each do |resolve|
          if !patch.nil? && patch != "No patch available" && package == resolve[:path]
            update_direct_dependency(package, patch, packages)
          end
        end
      end
      write_auto_fix_files(path_to_repo, 'package-autofixed.json', JSON.dump(packages))
    end

    def fix_indirect_dependency(_feed, yarn_lock, _path_to_repo)
      parsed_yarn_lock = Salus::YarnLockfileFormatter.new(yarn_lock).format
      yaml = parsed_yarn_lock.to_yaml
    
      s = ""
      yaml.each do |item|
        s += item + "\n"
      end

      puts s.gsub("---\n", '\n')

      subparent_to_package_mapping = []
    end

    def get_package_info(package, version = nil)
      info = if version.nil?
               run_shell("yarn info #{package} --json", chdir: File.expand_path(@path_to_repo))
             else
               run_shell(
                 "yarn info #{package}@#{version} --json",
                 chdir: File.expand_path(@path_to_repo)
               )
             end
      JSON.parse(info.stdout)
    rescue StandardError
      nil
    end

    def is_major_bump(current, updated)
      current.gsub(/[^0-9.]/, "")
      current_v = current.split('.').map(&:to_i)
      updated.sub(/[^0-9.]/, "")
      updated_v = updated.split('.').map(&:to_i)
      return true if updated_v.first > current_v.first

      false
    end

    def update_direct_dependency(package, patched_version_range, packages)
      if patched_version_range.match(Salus::SemanticVersion::SEMVER_RANGE_REGEX).nil?
        raise AutofixError, "Found unexpected: patched version range: #{patched_version_range}"
      end

      vulnerable_package_info = get_package_info(package)
      list_of_versions = vulnerable_package_info.dig("data", "versions")

      if list_of_versions.nil?
        error_msg = "#yarn info command did not provide a list of available package versions"
        raise AutofixError, error_msg
      end

      patched_version = Salus::SemanticVersion.select_upgrade_version(
        patched_version_range,
        list_of_versions
      )

      if !patched_version.nil?
        %w[dependencies resolutions devDependencies].each do |package_section|
          if !packages.dig(package_section, package).nil?
            current_version = packages[package_section][package]
            if !is_major_bump(current_version, patched_version)
              packages[package_section][package] = "^#{patched_version}"
            end
          end
        end
      end
    end
  end
end
