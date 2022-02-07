require 'salus/scanners/github_advisory/base'

module Salus::Scanners::GithubAdvisory
  class GoGithubAdvisory < Base
    class SemVersion < Gem::Version; end

    def self.supported_languages
      %w[go]
    end

    def run_github_advisory_scan?
      @repository.go_mod_present? && @repository.go_sum_present?
    end

    def find_dependencies
      # Return a map of dependency name and versions used by the project
      all_dependencies = []
      chosen_dependencies = {}

      # Determine go version to check if 'go mod graph' can be ran.
      version_shell = run_shell("go mod edit -json")
      begin
        shell_return_json = JSON.parse(version_shell.stdout)
      rescue JSON::ParserError => e
        error_msg = "GoGithubAdvisory: Failed to parse results of 'go mod edit -json' " \
                    "to determine go version."
        bugsnag_notify(e.message)
        report_error(error_msg)
        return
      end

      # Run go mod graph
      # Returns lines in the format of -
      # cloud.google.com/go@v0.74.0 golang.org/x/text@v0.3.4
      if shell_return_json.key?("Go")
        if SemVersion.new(shell_return_json["Go"]) >= SemVersion.new("1.16")
          raw = run_shell("go mod graph", chdir: @repository.path_to_repo).stdout
          raw.each_line do |line|
            direct, indirect = line.split(" ")
            all_dependencies.append({
                                      "name": direct.split("@")[0].to_s,
                                "version": direct.split("@")[1].to_s
                                    })
            all_dependencies.append({
                                      "name": indirect.split("@")[0].to_s,
                                "version": indirect.split("@")[1].to_s
                                    })
          end
        end
      end

      # If go mod graph fails / go version less than 1.16, default to go.sum
      if all_dependencies.empty?
        go_sum_path = "#{@repository.path_to_repo}/go.sum"
        File.foreach(go_sum_path).each("=\n") do |line|
          line = line.strip
          next if line.empty?

          go_sum_regex = %r{(?<namespace>(.*)(?!/go\.mod))/(?<name>[^\s]*)
          (\s)*(?<version>(.*))(\s)*h1:(?<checksum>(.*))}x

          if (matches = line.match(go_sum_regex))
            all_dependencies.append(
              {
                "name": (matches[:namespace] + "/" + matches[:name]).to_s,
                "version": (matches[:version]).to_s.gsub(%r{/go.mod}, '').strip
              }
            )
          end
        end
      end

      # Pick specific version of dependencies
      # If multiple versions of dependencies are found then pick the max version to mimic MVS
      # https://go.dev/ref/mod#go-mod-graph, https://go.dev/ref/mod#minimal-version-selection
      all_dependencies.each do |deps|
        lib = deps[:name]
        version = deps[:version].to_s.gsub('v', '').gsub('+incompatible', '')
        if chosen_dependencies.key?(lib)
          temp = chosen_dependencies[lib]
          chosen_dependencies[lib] = version if SemVersion.new(version) > SemVersion.new(temp)
        else
          chosen_dependencies[lib] = version
        end
      end
      chosen_dependencies
    end

    def run
      results = []
      # Find dependencies from the project
      dependencies = find_dependencies
      if dependencies.empty?
        msg = "Failed to parse any dependencies from the project."
        return report_error("GoGithubAdvisory: #{msg}")
      end

      # Match dependencies found with advisories from Github
      if github_advisories.nil?
        msg = "No advisories found to compare."
        return report_error("GoGithubAdvisory: #{msg}")
      else
        dependencies.each do |lib, version|
          package_matches = github_advisories.select { |v| v.dig("package", "name") == lib }
          package_matches.each do |m|
            version_match_found = false
            version_ranges = m.dig("vulnerableVersionRange").split(', ')
            # Version Ranges can have 2 formats: > x.x OR > x.x, < x.y
            if version_ranges.length == 1
              version_match_found = SemDependency.new('', version_ranges[0]).match?('', version)
            elsif version_ranges.length == 2
              version_match_found = SemDependency.new('', version_ranges[0]).match?('', version) &&
                SemDependency.new('', version_ranges[1]).match?('', version)
            end
            if version_match_found
              results.append({
                               "Package": m.dig("package", "name"),
                  "Vulnerable Version": m.dig("vulnerableVersionRange") || "Not Found",
                  "Version Detected": version,
                  "Patched Versions": m.dig("firstPatchedVersion", "identifier") || "Not Found",
                  "Summary": m.dig("advisory", "summary") || "Not Found",
                  "Severity": m.dig("advisory", "severity") || "Not Found",
                  "ID": m["advisory"]["identifiers"][0]["value"] || "Not Found",
                  "References": m.dig("advisory", "references").collect { |p| p["url"].to_s },
                  "Source": "RUN go mod graph OR Check go.sum"
                             })
            end
          end
        end
      end

      # Report scanner status
      if results.any?
        # results.append({
        #                  "NOTE": "Affected packages were found using - \n" \
        #                  "1. 'go mod graph' results OR" \
        #                  "\n2. 'go.sum' file." \
        #                })
        log(JSON.pretty_generate(results))
        report_failure
      else
        report_success
      end
    end
  end
end
