require 'json'
require 'salus/scanners/node_audit'

# Yarn Audit scanner integration. Flags known malicious or vulnerable
# dependencies in javascript projects that are packaged with yarn.
# https://yarnpkg.com/en/docs/cli/audit

module Salus::Scanners
  class YarnAudit < NodeAudit
    # the command was previously 'yarn audit --json', which had memory allocation issues
    # see https://github.com/yarnpkg/yarn/issues/7404
    LEGACY_YARN_AUDIT_COMMAND = 'yarn audit --no-color'.freeze
    LATEST_YARN_AUDIT_ALL_COMMAND = 'yarn npm audit --all --json'.freeze
    LATEST_YARN_AUDIT_PROD_COMMAND = 'yarn npm audit --environment'\
                  ' production --json'.freeze
    YARN_VERSION_COMMAND = 'yarn --version'.freeze
    BREAKING_VERSION = "2.0.0".freeze

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
