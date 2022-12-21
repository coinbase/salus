require 'uri'
require 'salus/yarn_formatter'
require 'salus/auto_fix/base'

module Salus::Autofix
  class YarnAuditV1 < Base
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
      write_auto_fix_files(path_to_repo, 'package-autofixed.json', JSON.pretty_generate(packages))
    end

    def fix_indirect_dependency(feed, yarn_lock, path_to_repo)
      @parsed_yarn_lock = Salus::YarnLockfileFormatter.new(yarn_lock).format
      subparent_to_package_mapping = []

      feed.each do |vuln|
        patch = vuln[:target]
        resolves = vuln[:resolves]
        package = vuln[:module]
        resolves.each do |resolve|
          if !patch.nil? && patch != "No patch available" && package != resolve[:path]
            block = create_subparent_to_package_mapping(resolve[:path])
            if block.key?(:key)
              block[:patch] = patch
              subparent_to_package_mapping.append(block)
            end
          end
        end
      end
      parts = yarn_lock.split(/^\n/)
      parts = update_sub_parent_resolution(subparent_to_package_mapping, parts)
      parts = update_package_definition(subparent_to_package_mapping, parts)
      # TODO: Run clean up task
      write_auto_fix_files(path_to_repo, 'yarn-autofixed.lock', parts.join("\n"))
    end

    # In yarn.lock, we attempt to update yarn.lock entries for the package
    def update_package_definition(blocks, parts)
      blocks.uniq { |hash| hash.values_at(:prev, :key, :patch) }
      group_updates = blocks.group_by { |h| [h[:prev], h[:key]] }
      group_updates.each do |updates, versions|
        updates = updates.last
        vulnerable_package_info = get_package_info(updates)
        list_of_versions_available = vulnerable_package_info["data"]["versions"]
        version_to_update_to = Salus::SemanticVersion.select_upgrade_version(
          versions.first[:patch], list_of_versions_available
        )
        package_name = updates.reverse.split('@', 2).collect(&:reverse).reverse.first
        if !version_to_update_to.nil?
          fixed_package_info = get_package_info(package_name, version_to_update_to)
          unless fixed_package_info.nil?
            updated_version = "version " + '"' + version_to_update_to + '"'
            updated_resolved = "resolved " + '"' + fixed_package_info["data"]["dist"]["tarball"] \
              + "#" + fixed_package_info["data"]["dist"]["shasum"] + '"'
            updated_integrity = "integrity " + fixed_package_info['data']['dist']['integrity']
            updated_name = package_name + "@^" + version_to_update_to

            parts.each_with_index do |part, index|
              current_v = parts[index].match(/(("|)version("|).*)/)
              version_string = current_v.to_s.tr('"', "").tr("version ", "")
              if part.include?(updates) && !is_major_bump(
                version_string, version_to_update_to
              ) && part.start_with?(updates.split("@")[0])
                current_source = parts[index].match(/(("|)resolved("|).*)/)
                source = current_source.to_s.split(" ")[1].tr('"', '')
                current_hostname = URI.parse(source)
                resolved_source = updated_resolved.split(" ")[1].tr('"', '')
                resolved_hostname = URI.parse(resolved_source)
                updated_resolved.sub!(resolved_hostname.host, current_hostname.host)

                parts[index].sub!(updates, updated_name)
                parts[index].sub!(/(("|)version("|).*)/, updated_version)
                parts[index].sub!(/(("|)resolved("|).*)/, updated_resolved)
                parts[index].sub!(/(("|)integrity("|).*)/, updated_integrity)
              end
            end
          end
        end
      end
      parts
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

    def is_major_bump(current_version, new_version)
      current_version.gsub!(/[^0-9.]/, "")
      new_version.gsub!(/[^0-9.]/, "")
      unless current_version.empty? && new_version.empty?
        current_v = if current_version.include? "."
                      current_version.split('.').map(&:to_i)
                    else
                      [current_version.to_i]
                    end

        new_v = if new_version.include? "."
                  new_version.split('.').map(&:to_i)
                else
                  [new_version.to_i]
                end
        return true if new_v.first > current_v.first
      end

      false
    end

    # In yarn.lock, we attempt to resolve sub parent of the affected package to
    # new updated package definition.
    def update_sub_parent_resolution(blocks, parts)
      blocks.uniq { |hash| hash.values_at(:prev, :key, :patch) }
      group_appends = blocks.group_by { |h| [h[:prev], h[:key]] }
      group_appends.each do |pair, patch|
        source = pair.first
        target = pair.last.reverse.split('@', 2).collect(&:reverse).reverse.first
        vulnerable_package_info = get_package_info(target)
        list_of_versions_available = vulnerable_package_info["data"]["versions"]
        version_to_update_to = Salus::SemanticVersion.select_upgrade_version(
          patch.first[:patch], list_of_versions_available
        )
        if !version_to_update_to.nil?
          parts.each_with_index do |part, index|
            match = part.match(/("|)(!:|#{target})("| ).*/)
            if part.include?(source) && !match.nil? && !is_major_bump(
              match.to_s.split(" ").last, version_to_update_to
            )
              replace = target + ' "^' + version_to_update_to + '"'
              part.sub!(/("|)(!:|#{target})("| ).*/, replace)
              parts[index] = part
            end
          end
        end
      end
      parts
    end

    def create_subparent_to_package_mapping(path)
      section = {}
      packages = path.split(" > ")
      packages.each_with_index do |package, index|
        break if index == packages.length - 1

        section = if index.zero?
                    find_section_by_name(package, packages[index + 1])
                  else
                    find_section_by_name_and_version(
                      section[:key],
                      packages[index + 1]
                    )
                  end
      end
      section
    end

    def find_section_by_name(name, next_package)
      @parsed_yarn_lock.each do |key, array|
        if key.starts_with? "#{name}@"
          %w[dependencies optionalDependencies].each do |section|
            if array[section]&.[](next_package)
              value = array.dig(section, next_package)
              return { "prev": key, "key": "#{next_package}@#{value}" }
            end
          end
        end
      end
      {}
    end

    def find_section_by_name_and_version(name, next_package)
      @parsed_yarn_lock.each do |key, array|
        if key == name
          %w[dependencies optionalDependencies].each do |section|
            if array[section]&.[](next_package)
              value = array.dig(section, next_package)
              return { "prev": key, "key": "#{next_package}@#{value}" }
            end
          end
        end
      end
      {}
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
