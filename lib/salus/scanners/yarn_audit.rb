require 'json'
require 'salus/scanners/node_audit'
require 'salus/versions'

# Yarn Audit scanner integration. Flags known malicious or vulnerable
# dependencies in javascript projects that are packaged with yarn.
# https://yarnpkg.com/en/docs/cli/audit

module Salus::Scanners
  class YarnAudit < NodeAudit
    class SemVersion < Gem::Version; end
    class ExportReportError < StandardError; end
    # the command was previously 'yarn audit --json', which had memory allocation issues
    # see https://github.com/yarnpkg/yarn/issues/7404
    LEGACY_YARN_AUDIT_COMMAND = 'yarn audit --no-color'.freeze
    LATEST_YARN_AUDIT_ALL_COMMAND = 'yarn npm audit --json'.freeze
    LATEST_YARN_AUDIT_PROD_COMMAND = 'yarn npm audit --environment'\
                  ' production --json'.freeze
    YARN_VERSION_COMMAND = 'yarn --version'.freeze
    BREAKING_VERSION = "2.0.0".freeze
    YARN_COMMAND = 'yarn'.freeze

    def should_run?
      @repository.yarn_lock_present?
    end

    def self.scanner_type
      Salus::ScannerTypes::DEPENDENCY
    end

    def run
      @vulns_w_paths = []
      if Gem::Version.new(version) >= Gem::Version.new(BREAKING_VERSION)
        handle_latest_yarn_audit
      else
        handle_legacy_yarn_audit
      end
    end

    def handle_latest_yarn_audit
      vulns = []
      dep_types = @config.fetch('exclude_groups', [])
      audit_command = if dep_types.include?('devDependencies')
                        LATEST_YARN_AUDIT_PROD_COMMAND
                      else
                        LATEST_YARN_AUDIT_ALL_COMMAND
                      end
      scan_depth = if @config.fetch('scan_depth', []).present?
                     '--' + @config.fetch('scan_depth').join('')
                   else
                     ''
                   end
      command = "#{audit_command} #{scan_depth}"
      shell_return = run_shell(command)
      excpts = fetch_exception_ids
      report_info(:ignored_cves, excpts)

      begin
        data = JSON.parse(shell_return.stdout)
      rescue JSON::ParserError
        err_msg = "YarnAudit: Could not parse JSON returned by #{command}"
        report_stderr(err_msg)
        report_error(err_msg)
        return []
      end

      data["advisories"].each do |advisory_id, advisory|
        if excpts.exclude?(advisory_id)
          dependency_of = advisory["findings"]&.first&.[]("paths")
          vulns.append({
                         "Package" => advisory.dig("module_name"),
                         "Patched in" => advisory.dig("patched_versions"),
                         "More info" => advisory.dig("url"),
                         "Severity" => advisory.dig("severity"),
                         "Title" => advisory.dig("title"),
                         "ID" => advisory_id.to_i,
                         "Dependency of" => if dependency_of.nil?
                                              advisory.dig("module_name")
                                            else
                                              dependency_of.join("")
                                            end
                       })
        end
      end
      return report_success if vulns.empty?

      vulns = combine_vulns(vulns)
      log(format_vulns(vulns))
      report_stdout(vulns.to_json)
      report_failure
    end

    def handle_legacy_yarn_audit
      command = "#{LEGACY_YARN_AUDIT_COMMAND} #{scan_deps}"
      shell_return = run_shell(command)

      excpts = fetch_exception_ids.map(&:to_i)
      report_info(:ignored_cves, excpts)
      return report_success if shell_return.success?

      stdout_lines = shell_return.stdout.split("\n")
      table_start_pos = stdout_lines.index { |l| l.start_with?("┌─") && l.end_with?("─┐") }
      table_end_pos = stdout_lines.rindex { |l| l.start_with?("└─") && l.end_with?("─┘") }

      # if no table in output
      if table_start_pos.nil? || table_end_pos.nil?
        report_error(shell_return.stderr, status: shell_return.status)
        report_stderr(shell_return.stderr)
        return report_failure
      end

      table_lines = stdout_lines[table_start_pos..table_end_pos]
      # lines contain 1 or more vuln tables

      vulns = parse_output(table_lines)
      @vulns_w_paths = deep_copy_wo_paths(vulns)
      vulns.each { |vul| vul.delete('Path') }
      vuln_ids = vulns.map { |v| v['ID'] }
      report_info(:vulnerabilities, vuln_ids.uniq)

      vulns.reject! { |v| excpts.include?(v['ID']) }
      # vulns were all whitelisted
      return report_success if vulns.empty?

      chdir = File.expand_path(@repository&.path_to_repo)

      Salus::YarnLock.new(File.join(chdir, 'yarn.lock')).add_line_number(vulns)

      run_auto_fix

      vulns = combine_vulns(vulns)
      log(format_vulns(vulns))
      report_stdout(vulns.to_json)
      report_failure
    end

    def version
      shell_return = run_shell(YARN_VERSION_COMMAND)
      # stdout looks like "1.22.0\n"
      shell_return.stdout&.strip
    end

    def self.supported_languages
      ['javascript']
    end

    private

    def parse_output(lines)
      vulns = Set.new

      i = 0
      while i < lines.size
        if lines[i].start_with?("┌─") && lines[i].end_with?("─┐")
          vuln = {}
        elsif lines[i].start_with? "│ "
          line_split = lines[i].split("│")
          curr_key = line_split[1].strip
          val = line_split[2].strip
          if curr_key != ""
            vuln[curr_key] = val
            prev_key = curr_key
          else
            vuln[prev_key] += ' ' + val
          end
        elsif lines[i].start_with?("└─") && lines[i].end_with?("─┘")
          vulns.add(vuln)
        end
        i += 1
      end

      vulns = vulns.to_a
      vulns.each { |vln| normalize_vuln(vln) }.sort { |a, b| a['ID'] <=> b['ID'] }
    end

    def scan_deps
      dep_types = @config.fetch('exclude_groups', [])

      return '' if dep_types.empty?

      if dep_types.include?('devDependencies') &&
          dep_types.include?('dependencies') &&
          dep_types.include?('optionalDependencies')
        report_error("No dependencies were scanned!")
        return ''
      elsif dep_types.include?('devDependencies') && dep_types.include?('dependencies')
        report_warn(:scanner_misconfiguration, "Scanning only optionalDependencies!")
      end

      command = ' --groups '
      command << 'dependencies ' unless dep_types.include?('dependencies')
      command << 'devDependencies ' unless dep_types.include?('devDependencies')
      command << 'optionalDependencies ' unless dep_types.include?('optionalDependencies')
    end

    def find_nested_hash_value(obj, key)
      if obj.respond_to?(:key?) && obj.key?(key)
        obj[key]
      elsif obj.respond_to?(:each)
        r = nil
        obj.find { |*a| r = find_nested_hash_value(a.last, key) }
        r
      end
    end

    # severity and vuln title in the yarn output looks like
    # | low           | Prototype Pollution                                          |
    # which are stored in the vuln hash as "low" ==> "Prototype Pollution"
    # need to update that to
    #     1) "severity" => "low"
    #     2) "title" => "Prototype Pollution"
    #
    # Also, add a separate id field
    def normalize_vuln(vuln)
      sev_levels = %w[info low moderate high critical]

      sev_levels.each do |sev|
        if vuln[sev]
          vuln['Severity'] = sev
          vuln['Title'] = vuln[sev]
          vuln.delete(sev)
          break
        end
      end

      # "More info" looks like https://www.npmjs.com/advisories/1179
      # need to extract the id at the end
      id = vuln["More info"].split("https://www.npmjs.com/advisories/")[1]
      vuln['ID'] = id.to_i
    end

    def combine_vulns(vulns)
      uniq_vulns = {} # each key is uniq id

      vulns.each do |vul|
        id = vul['ID']
        if uniq_vulns[id]
          uniq_vulns[id]['Dependency of'].push vul['Dependency of']
        else
          uniq_vulns[id] = vul
          uniq_vulns[id]['Dependency of'] = [uniq_vulns[id]['Dependency of']]
        end
      end

      vulns = uniq_vulns.values
      vulns.each do |vul|
        vul['Dependency of'] = vul['Dependency of'].sort.join(', ')
      end
      vulns
    end

    def run_auto_fix
      # TODO: Preprocessing to combine vulns by path / max version
      fix_feed = []
      grouped_vulns = @vulns_w_paths.group_by { |h| h["Path"] }

      grouped_vulns.each do |key, array|
        fix_feed.append({
                          Path: key,
          Package: array.first["Package"],
          Patch: array.map { |x| x["Patched in"] }.sort.reverse.first
                        })
      end

      fix_feed.each do |vuln|
        path = vuln[:Path]
        package = vuln[:Package]
        if path == package
          fix_direct_dependency(vuln)
        else
          puts "Fixing Indirect Deps for #{vuln[:Package]}"
          fix_indirect_dependency(vuln)
        end
      end
      puts @repository.yarn_lock
    end

    def fix_direct_dependency(vuln)
      # update dependencies, devdependencies, resolution
      package = vuln["Package"]
      patched_version = vuln["Patched in"]

      vulnerable_package_info = run_shell("yarn info #{package} --json")
      vulnerable_package_info = JSON.parse(vulnerable_package_info.stdout)
      list_of_versions = vulnerable_package_info["data"]["versions"]
      version_to_update_to = select_upgrade_version(patched_version, list_of_versions)

      if @repository.package_json["dependencies"].key?(package)
        @repository.package_json["dependencies"][package] = "^#{version_to_update_to}"
      end

      if @repository.package_json["resolutions"].key?(package)
        @repository.package_json["resolutions"][package] = "^#{version_to_update_to}"
      end

      if @repository.package_json["devDependencies"].key?(package)
        @repository.package_json["devDependencies"][package] = "^#{version_to_update_to}"
      end
    end

    def fix_indirect_dependency(vuln)
      path = vuln[:Path]
      patched_version = vuln[:Patch]
      packages = path.split(" > ")

      # Find correct subsection to update
      sub_package_section = find_sub_section(packages)

      # Fetch current vulnerable version
      vulnerable_package_name = packages.last
      vulnerable_package_dependency = sub_package_section.to_s.match(
        /(#{vulnerable_package_name} .*)/
      )
      splits = vulnerable_package_dependency.to_s.split(" ", 2)
      current_vulnerable_package_version = splits[1].tr('"', '')
      puts "Updating #{vulnerable_package_dependency}"

      # if patched_version is major compared to current_vulnerable_package_version then abort

      # Fetch current vulnerable package metadata
      vulnerable_package_info = get_package_info(vulnerable_package_name)
      list_of_versions_available = vulnerable_package_info["data"]["versions"]

      # Fetch patched package metadata
      version_to_update_to = select_upgrade_version(patched_version, list_of_versions_available)
      fixed_package_info = get_package_info(vulnerable_package_name, version_to_update_to)

      # Override package definition to allow upgrades
      replace_patch_versions(
        vulnerable_package_dependency, version_to_update_to, vulnerable_package_name
      )

      # Update vulnerable package section
      @repository.yarn_lock.scan(/^("|)(#{vulnerable_package_name}.*?)\n\n/m).each do |section|
        # Validate its the correct block
        if section.join.include? "#{vulnerable_package_name}@#{current_vulnerable_package_version}"
          block = section.join
          update_block(
            version_to_update_to, fixed_package_info, section, block, vulnerable_package_dependency,
            vulnerable_package_name
          )
        end
      end
    end

    def find_sub_section(paths)
      blob = name = version = ""
      paths.each_with_index do |path, index|
        # section = @repository.yarn_lock.match(/^("|)(#{path}@.*?)\n\n/m)
        break if index == paths.length - 1

        @repository.yarn_lock.scan(/^("|)(#{path}@.*?)\n\n/m).each do |section|
          if index.zero?
            sub_section = section.join.match(/(#{paths[index + 1]}.*)/)
            splits = sub_section.to_s.split(" ", 2)
            name = splits.first
            version = splits.last.delete_prefix('"').delete_suffix('"')
          elsif index.positive? && section.to_s.include?("#{name}@#{version}")
            sub_section = section.join.match(/(#{paths[index + 1]}.*)/)
            splits = sub_section.to_s.split(" ", 2)
            name = splits.first
            version = splits.last.delete_prefix('"').delete_suffix('"')
          end
          blob = section.join
        end
      end
      blob
    end

    def get_package_info(package, version = nil)
      info = if version.nil?
               run_shell("yarn info #{package} --json")
             else
               run_shell("yarn info #{package}@#{version} --json")
             end
      JSON.parse(info.stdout)
    end

    def replace_patch_versions(dependency, version_to_update_to, package_name)
      puts "Stuff to replace #{dependency}"
      s = package_name + ' "^' + version_to_update_to + '"'
      @repository.yarn_lock.gsub!(dependency.to_s, s)
    end

    def update_block(version, package_info, section, block, dependency, package_name)
      updated_version = "version " + '"' + version + '"'
      updated_resolved = "resolved " + '"' + package_info["data"]["dist"]["tarball"] + "#" \
          + package_info["data"]["dist"]["shasum"] + '"'
      updated_integrity = "integrity " + package_info['data']['dist']['integrity']
      header = package_name + '@^' + version

      splits = dependency.to_s.split(" ", 2)
      v = splits[1].tr('"', '')
      s = "#{package_name}@#{v}"
      if block.exclude? header
        block.sub!(s, header)
        block.sub!(/(version.*)/, updated_version)
        block.sub!(/(resolved.*)/, updated_resolved)
        block.sub!(/(integrity.*)/, updated_integrity)
        @repository.yarn_lock.sub!(section.join, block)
      end
    end

    def select_upgrade_version(patched_version, list_of_versions)
      list_of_versions.each do |version|
        if patched_version.include? ">="
          parsed_patched_version = patched_version.tr(">=", "").tr(">= ", "")
          return version if SemVersion.new(version) >= SemVersion.new(parsed_patched_version)
        end
      end
      nil
    end

    def deep_copy_wo_paths(vulns)
      vuln_list = []
      vulns.each do |vuln|
        vt = {}
        vuln.each { |k, v| vt[k] = v }
        vuln_list.push vt
      end
      vuln_list
    end

    def format_vulns(vulns)
      str = ""
      vulns.each do |vul|
        vul.each do |k, v|
          str += "#{k}: #{v}\n"
        end
        str += "\n"
      end
      str
    end
  end
end
