require 'json'
require 'salus/scanners/node_audit'

# Yarn Audit scanner integration. Flags known malicious or vulnerable
# dependencies in javascript projects that are packaged with yarn.
# https://yarnpkg.com/en/docs/cli/audit

module Salus::Scanners
  class YarnAudit < NodeAudit
    AUDIT_COMMAND = 'yarn audit --no-color'.freeze

    def should_run?
      @repository.yarn_lock_present?
    end

    def run
      shell_return = Dir.chdir(@repository.path_to_repo) do
        command = "#{AUDIT_COMMAND} #{scan_deps}"
        shell_return = run_shell(command)

        excpts = @config.fetch('exceptions', []).map { |e| e["advisory_id"].to_i }
        report_info(:ignored_cves, excpts)
        return report_success if shell_return.success?

        vulns = parse_output(shell_return.stdout)
        vuln_ids = vulns.map { |v| v['id'] }
        report_info(:vulnerabilities, vuln_ids.uniq)

        vulns.reject! { |v| excpts.include?(v['id']) }
        # vulns were all whitelisted
        return report_success if vulns.empty?

        log(format_vulns(vulns))
        report_stdout(vulns.to_json)
        report_failure
      end
    end

    def parse_output(out)
      table_top = "┌───────────────┬──────────────────────────────────────────────────────────────┐"
      table_bot = "└───────────────┴──────────────────────────────────────────────────────────────┘"
      empty_cell = "│               │"
      vulns = []
      lines = out.split("\n")

      table_start_pos = lines.index(table_top)
      table_end_pos = lines.rindex(table_bot)
      # lines contain 1 or more vuln tables
      lines = lines[table_start_pos..table_end_pos]

      if table_start_pos.nil? || table_end_pos.nil?
        report_stdout("Output has no vuln tables: #{out}")
        log(out)
      end

      i = 0
      while i < lines.size
        if lines[i] == table_top
          vuln = {}
        elsif lines[i] =~ /^\│ [A-Za-z]/
          # line has attr name and val, like
          # | Path          | eslint > file-entry-cache > flat-cache > write > mkdirp >    |
          line_split = lines[i].split("│")
          key = line_split[1].strip
          val = line_split[2].strip
          vuln[key] = val
        elsif lines[i].start_with?(empty_cell)
          # multi-line attribute val, like the 2nd line here
          # | Path          | eslint > file-entry-cache > flat-cache > write > mkdirp >    |
          # |               | minimist                                                     |
          val = lines[i].split(empty_cell)[1].split("│")[0].strip
          vuln[key] += ' ' + val
        elsif lines[i] == table_bot
          vulns.push vuln
        end
        i += 1
      end

      vulns.each { |vln| normalize_vuln(vln) }
    end

    private

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
          vuln['severity'] = sev
          vuln['title'] = vuln[sev]
          vuln.delete(sev)
          break
        end
      end

      # "More info" looks like https://www.npmjs.com/advisories/1179
      # need to extract the id at the end
      id = vuln["More info"].split("https://www.npmjs.com/advisories/")[1]
      vuln['id'] = id.to_i
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
