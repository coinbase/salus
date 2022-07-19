require 'json'
require 'salus/scanners/node_audit'

# NPM Audit scanner integration. Flags known malicious or vulnerable
# dependencies in javascript projects.
# https://medium.com/npm-inc/npm-acquires-lift-security-258e257ef639

module Salus::Scanners
  class NPMAudit < NodeAudit
    AUDIT_COMMAND = 'npm audit --json'.freeze

    def self.scanner_type
      Salus::ScannerTypes::DEPENDENCY
    end

    def should_run?
      @repository.package_lock_json_present? && @repository.package_json_present?
    end

    def version
      shell_return = run_shell('npm audit --version')
      # stdout looks like "6.14.8\n"
      shell_return.stdout&.strip
    end

    def self.supported_languages
      ['javascript']
    end

    private

    def prod_only_audit_command
      command = AUDIT_COMMAND
      command += " --only=prod"
      command
    end

    def scan_for_cves(chdir: File.expand_path(@repository&.path_to_repo))
      if @config["production"] == true
      else
      end
      raw = run_shell(prod_only_audit_command).stdout
      json = JSON.parse(raw, symbolize_names: true)

      if json.key?(:error)
        code = json[:error][:code] || '<none>'
        summary = json[:error][:summary] || '<none>'

        message =
          "`#{prod_only_audit_command}` failed unexpectedly (error code #{code}):\n" \
          "```\n#{summary}\n```"

        raise message
      end
      
      report_stdout(json)


      if !json.has_key?(:vulnerabilities)
        if json[:advisories] && !json[:advisories].empty?
          Salus::PackageLockJson.new(File.join(chdir, 'package-lock.json')).add_line_number(json)
        end
  
        return json.fetch(:advisories).values
      else
        all_vulns = json.fetch(:vulnerabilities).map do |_, dependency_vulns|
          dependency_vulns.fetch(:via)
        end
  
        all_vulns = all_vulns.flatten
  
        all_vulns.each do |vuln|
          vuln[:module_name] = vuln.delete :name
          vuln[:id] = vuln.delete :source
        end

        return all_vulns
      end
    end
  end
end
