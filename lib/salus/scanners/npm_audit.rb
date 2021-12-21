require 'json'
require 'salus/scanners/node_audit'

# NPM Audit scanner integration. Flags known malicious or vulnerable
# dependencies in javascript projects.
# https://medium.com/npm-inc/npm-acquires-lift-security-258e257ef639

module Salus::Scanners
  class NPMAudit < NodeAudit
    AUDIT_COMMAND = 'npm audit --json'.freeze

    def should_run?
      @repository.package_lock_json_present?
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

    def audit_command_with_options
      command = AUDIT_COMMAND
      command += " --production" if @config["production"] == true
      command
    end

    def scan_for_cves
      @deps = {}
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

      add_line_locs_to_advisories(json) if json[:advisories] && !json[:advisories].empty?
      report_stdout(json)

      json.fetch(:advisories).values
    end

    def add_line_locs_to_advisories(json)
      record_dep_locations

      json[:advisories].each do |_id, vul_info|
        dep_name = vul_info[:module_name]
        vul_version = vul_info[:findings].map { |v| v[:version] }.min
        vul_info[:line_number] = @deps[dep_name][vul_version] if @deps[dep_name][vul_version]
      end
    end

    # Store line numbers of dependencies in @dep. Ex
    # { "dep_name " =>
    #    { "1.0.0" => 10   # version 1.0.0 => line 10
    #      "2.0.0" => 20   # version 2.0.0 => line 20
    #    }
    # }
    def record_dep_locations
      content = File.read('package-lock.json')
      data = JSON.parse(content)
      get_dep_names(data)
      curr_line = 0
      lines = content.split("\n")
      lines.each do |line|
        line.strip!
        # if line with dependency name, like
        #   "math-random": {
        start_chars = "\": {"
        if line.end_with?(start_chars) && line.start_with?("\"")
          quote_index2 = line[1..].index(start_chars)
          dep_name = line[1..quote_index2]
          # right now version is always one line below the dependency name, like
          #    "math-random": {
          #      "version": "1.2.3",
          if @deps[dep_name] && lines[curr_line + 1]
            next_line = lines[curr_line + 1].strip
            if next_line.start_with?("\"version\": \"") && next_line.end_with?("\",")
              version = next_line[12..-3].strip
              @deps[dep_name][version] = curr_line + 2
            end
          end
        end
        curr_line += 1
      end
    end

    # recursively store all dependency names as keys
    def get_dep_names(data)
      data['dependencies'].each do |name, dep_info|
        @deps[name] = {}
        get_dep_names(dep_info) if dep_info['dependencies']
      end
    end
  end
end
