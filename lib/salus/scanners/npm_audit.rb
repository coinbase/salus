require 'fileutils'
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

    def auto_fix
      puts "**** RUNNING NPM AUTO FIX ****"
      file_map = {}
      cmd = "npm audit fix"
      res = nil
      Dir.chdir(@repository.path_to_repo) do
        res = run_shell(cmd)
        puts "Result from #{cmd} = #{res.inspect}"
      end

      if res.success?
        file_map = {
          'package-lock.json' => 'package-lock.json.autofix',
          'package.json' => 'package.json.autofix'
        }
        file_map.each do |name, new_name|
          name = File.join(@repository.path_to_repo, name)
          new_name = File.join(@repository.path_to_repo, new_name)
          FileUtils.cp(name, new_name)
        end
      else
        puts "ERROR! #{cmd} failed"
      end

      # if success then file_map maps updated files to new names
      # if failure then file_map remains empty map
      file_map
    end

    private

    def audit_command_with_options
      command = AUDIT_COMMAND
      command += " --production" if @config["production"] == true
      command
    end

    def scan_for_cves(chdir: File.expand_path(@repository&.path_to_repo))
      raw = run_shell(audit_command_with_options).stdout
      json = JSON.parse(raw, symbolize_names: true)

      if json.key?(:error)
        code = json[:error][:code] || '<none>'
        summary = json[:error][:summary] || '<none>'

        message =
          "`#{audit_command_with_options}` failed unexpectedly (error code #{code}):\n" \
          "```\n#{summary}\n```"

        raise message
      end

      if json[:advisories] && !json[:advisories].empty?
        Salus::PackageLockJson.new(File.join(chdir, 'package-lock.json')).add_line_number(json)
      end
      report_stdout(json)

      json.fetch(:advisories).values
    end
  end
end
