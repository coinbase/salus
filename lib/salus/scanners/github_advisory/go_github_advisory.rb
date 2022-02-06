require 'salus/scanners/github_advisory/base'

module Salus::Scanners::GithubAdvisory
  class GoGithubAdvisory < Base
    class SemVersion < Gem::Version; end

    def self.supported_languages
      %w[go]
    end

    def run
      dependencies = find_repo_dependencies
      if dependencies.nil? && github_query.nil?
        error_msg = "No dependencies or ecosystem were found"
        return report_error(error_msg)
      end
      results = []
      unless github_advisories.nil?
        dependencies.each do |lib, version|
          vulns = github_advisories.select { |v| v["package"]["name"] == lib }
          vulns.each do |vuln|
            vers = vuln["vulnerableVersionRange"].split(', ')
            if vers.length == 1
              if SemDependency.new('', vers[0]).match?('', version)
                results.append({
                                 "Package": vuln.dig("package", "name"),
                    "Vulnerable Version": vuln.dig("vulnerableVersionRange"),
                    "Version Detected": version,
                    "Patched Versions": vuln.dig("firstPatchedVersion", "identifier") || "Not Found",
                    "Summary": vuln.dig("advisory", "summary"),
                    "Severity": vuln.dig("advisory", "severity"),
                    "ID": vuln["advisory"]["identifiers"][0]["value"],
                    "References": vuln["advisory"]["references"].collect { |p| p["url"].to_s },
                    "Source": "Github Advisory"
                               })
              end
            elsif vers.length == 2
              if SemDependency.new('', vers[0]).match?('', version) &&
                  SemDependency.new('', vers[1]).match?('', version)
                results.append({
                                 "Package": vuln.dig("package", "name"),
                    "Vulnerable Version": vuln.dig("vulnerableVersionRange"),
                    "Version Detected": version,
                    "Patched Versions": vuln.dig("firstPatchedVersion", "identifier") || "Not Found",
                    "Summary": vuln.dig("advisory", "summary"),
                    "Severity": vuln.dig("advisory", "severity"),
                    "ID": vuln["advisory"]["identifiers"][0]["value"],
                    "References": vuln["advisory"]["references"].collect { |p| p["url"].to_s },
                    "Source": "Github Advisory"
                               })
              end
            else
              next
            end
          end
        end
        results
      end

      # TODO: - Logic for handling excpetion
      # exceptions = @config['exceptions']

      if results.any?
        results.append({
                         "NOTE": "Affected packages were flagged by checking - \n" \
                         "1. 'go mod graph' results" \
                         "\n2. 'go.sum' file." \
                       })
        log(format_vulns(results))
        report_failure
      else
        report_success
      end
    end

    def find_repo_dependencies
      dep_list = []
      dependencies = {}

      version_shell = run_shell("go mod edit -json")
      shell_return_json = JSON.parse(version_shell.stdout)

      if SemVersion.new(shell_return_json["Go"]) >= SemVersion.new("1.16")
        # Checks for both direct and indirect deps
        # still not a complete check but a conservative approximation
        # "go list -m all"
        raw = run_shell("go mod graph", chdir: @repository.path_to_repo).stdout
        raw.each_line do |line|
          direct, indirect = line.split(" ")
          dep_list.append({
                            "name": direct.split("@")[0].to_s,
                            "version": direct.split("@")[1].to_s
                          })
          dep_list.append({
                            "name": indirect.split("@")[0].to_s,
                            "version": indirect.split("@")[1].to_s
                          })
        end
      end

      if dep_list.empty?
        go_sum_path = "#{@repository.path_to_repo}/go.sum"
        File.foreach(go_sum_path).each("=\n") do |line|
          line = line.strip
          next if line.empty?

          go_sum_regex = %r{(?<namespace>(.*)(?!/go\.mod))/(?<name>[^\s]*)
          (\s)*(?<version>(.*))(\s)*h1:(?<checksum>(.*))}x

          if (matches = line.match(go_sum_regex))
            dep_list.append(
              {
                "name": (matches[:namespace] + "/" + matches[:name]).to_s,
                "version": (matches[:version]).to_s.gsub(%r{/go.mod}, '').strip,
                "checksum": (matches[:checksum]).to_s
              }
            )
          end
        end
      end
      # Pick max version of direct dep
      dep_list.each do |deps|
        # lib = deps["namespace"] + "/" + deps["name"]
        lib = deps[:name]
        version = deps[:version].to_s.gsub('v', '').gsub('+incompatible', '')
        if dependencies.key?(lib)
          temp_v = dependencies[lib]
          dependencies[lib] = version if SemVersion.new(version) > SemVersion.new(temp_v)
        else
          dependencies[lib] = version
        end
      end
      dependencies
    end

    def go_project?
      @repository.go_mod_present? || @repository.go_sum_present?
    end
  end
end
