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
    LATEST_YARN_AUDIT_ALL_COMMAND = 'yarn npm audit --all --json'.freeze
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

    def stub_vuln
      v = [{
        "type": "auditAdvisory",
          "data": {
            "resolution": {
              "id": "1070458",
              "path": "nanoid",
              "dev": false,
              "optional": false,
              "bundled": false
            },
            "advisory": {
              "findings": [
                {
                  "version": "3.1.3",
                  "paths": [
                    "mocha>nanoid"
                  ]
                }
              ],
              "metadata": "null",
              "vulnerable_versions": "<3.1.4",
              "module_name": "nanoid",
              "patched_versions": ">=3.1.31",
              "updated": "2022-06-03T22:26:34.000Z",
              "recommendation": "Upgrade to version 3.1.4 or later"
            }
          }
      },
           {
             "type": "auditAdvisory",
               "data": {
                 "resolution": {
                   "id": "1070458",
                   "path": "follow-redirects",
                   "dev": false,
                   "optional": false,
                   "bundled": false
                 },
                 "advisory": {
                   "findings": [
                     {
                       "version": "3.1.3",
                       "paths": [
                         "http-proxy>follow-redirects"
                       ]
                     }
                   ],
                   "metadata": "null",
                   "vulnerable_versions": "<3.1.4",
                   "module_name": "follow-redirects",
                   "patched_versions": ">=1.14.8",
                   "updated": "2022-06-03T22:26:34.000Z",
                   "recommendation": "Upgrade to version 3.1.4 or later"
                 }
               }
           }]
      v
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
      vuln_ids = vulns.map { |v| v['ID'] }
      report_info(:vulnerabilities, vuln_ids.uniq)

      vulns.reject! { |v| excpts.include?(v['ID']) }
      # vulns were all whitelisted
      return report_success if vulns.empty?

      chdir = File.expand_path(@repository&.path_to_repo)

      Salus::YarnLock.new(File.join(chdir, 'yarn.lock')).add_line_number(vulns)
      run_auto_fix_v2(stub_vuln)

      vulns = combine_vulns(vulns)
      # log(format_vulns(vulns))
      # report_stdout(vulns.to_json)
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

          if curr_key != "" && curr_key != 'Path'
            vuln[curr_key] = val
            prev_key = curr_key
          elsif curr_key == 'Path'
            prev_key = curr_key
          elsif prev_key != 'Path'
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

    def fix_direct_dependency(_package, _version)
      # update package.json
      package_json = JSON.parse(@repository.package_json)
    end

    def run_auto_fix_v1(vulnerabilities)
      updates = {}
      # This method forces indirect dependency updates
      # There is an issue with package - lerna
      yarn_lock = @repository.yarn_lock
      vulnerabilities.each do |vulnerability|
        package = vulnerability["Package"]
        dependency_of = vulnerability["Dependency of"]
        if package.eql? dependency_of
          fix_direct_dependency(package, version)
        else
          dependency_of.split(", ").each do |d|
            dependency_of_regex_without_quotes = /^(#{d}.*?)\n\n/m
            dependency_of_regex_with_quotes = /^("#{d}.*?)\n\n/m
            yarn_lock.gsub!(dependency_of_regex_without_quotes, '')
            yarn_lock.gsub!(dependency_of_regex_with_quotes, '')
          end
          package_regex_without_quotes = /^(#{package}.*?)\n\n/m
          package_regex_with_quotes = /^("#{package}.*?)\n\n/m
          yarn_lock.gsub!(package_regex_without_quotes, '')
          yarn_lock.gsub!(package_regex_with_quotes, '')
        end
      end
      puts yarn_lock

      # Run yarn install to regenerate yarn.lock file
      # Return contents of package.json and yarn.lock as results
      # reinstall_dependencies = run_shell(YARN_COMMAND)
      # puts reinstall_dependencies.stdout
      # puts yarn_lock
      # write_report_to_file('file://yarn-new.lock', @repository.yarn_lock)
      updates
    end

    def run_auto_fix_v2(vulnerability)
      # package_json = JSON.parse(@repository.package_json)
      # yarn_lock = @repository.yarn_lock
      vulnerability.each do |v|
        package = v[:data][:advisory][:module_name]
        paths = v[:data][:advisory][:findings][0][:paths]
        patched_version = v[:data][:advisory][:patched_versions]
        paths.each do |path|
          if path == package
            puts "Direct dependency"
            fix_direct_dependency_v2(package, patched_version)
          else
            puts "Indirect dependency"
            fix_indirect_dependency_v2(path, patched_version)
          end
        end
      end
      # write_report_to_file("yarn-new.lock", @repository.yarn_lock)
      puts @repository.yarn_lock
    end

    def fix_direct_dependency_v2(package, patched_version)
      # update dependencies, devdependencies, resolution
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

    def fix_indirect_dependency_v2(path, patched_version)
      # TODO
      # 1. better parsing of dependency block - handle quotes / no quotes / avoid substring match
      # 2. Update parent block to use caret if fixed dependency
      # 3. Handle private registries
      # 4. In vulns sometimes there are multiple advisories and when one is saying go to 1.1.1 
      # and other is saying go to 1.1.2
      # select the higher version to go.
      # 5. Error handling and when to fail updates
      packages = path.split(">")
      vulnerable_package = packages.last
      parent_package = packages[packages.length - 2]

      # find subparent block to understand heirarchy
      parent_package_regex = /^(#{parent_package}@.*?)\n\n/m
      parent_section = @repository.yarn_lock.match(parent_package_regex)
      dependency = parent_section.to_s.match(/(#{vulnerable_package} .*)/)

      # get current package info
      vulnerable_package_info = get_package_info(vulnerable_package)

      if dependency
        list_of_versions = vulnerable_package_info["data"]["versions"]
        # we have the version we know to update to, new package info and where to replace
        version_to_update_to = select_upgrade_version(patched_version, list_of_versions)
        updated_package_info = get_package_info(vulnerable_package, version_to_update_to)
        splits = dependency.to_s.split(" ", 2)
        name = splits[0]
        current_version = splits[1].tr('"', '')

        # Override package definition to allow upgrades
        allow_patch_versions(dependency, current_version, version_to_update_to)

        # Search for the block to replace
        @repository.yarn_lock.scan(/^("|)(#{name}.*?)\n\n/m).each do |subsection|
          # Validate its the correct block
          if subsection.join.include? "#{name}@#{current_version}"
            temp = subsection.join
            updates = get_updated_block(version_to_update_to, updated_package_info)
            if updates
              temp.sub!(/(version.*)/, updates[:version])
              temp.sub!(/(resolved.*)/, updates[:resolved])
              temp.sub!(/(integrity.*)/, updates[:integrity])
              @repository.yarn_lock.sub!(subsection.join, temp)
            end
          end
        end
      end
    end

    def get_package_info(package, version = nil)
      info = if version.nil?
               run_shell("yarn info #{package} --json")
             else
               run_shell("yarn info #{package}@#{version} --json")
             end
      JSON.parse(info.stdout)
    end

    def allow_patch_versions(dependency, current_version, version_to_update_to)
      # ~version	Approximately equivalent to version, i.e., only accept new patch versions
      # ^version	Compatible with version, i.e., accept new minor and patch versions
      if current_version.exclude?("^") || current_version.include?("~")
        @repository.yarn_lock.sub!(/#{dependency}/, name + ' "^' + version_to_update_to + '"')
      end
    end

    def get_updated_block(version, package_info)
      updates = {
        version: "version " + '"' + version + '"',
        resolved: "resolved " + '"' + package_info["data"]["dist"]["tarball"] + "#" \
          + package_info["data"]["dist"]["shasum"] + '"',
        integrity: "integrity " + package_info['data']['dist']['integrity']
      }
      updates
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
