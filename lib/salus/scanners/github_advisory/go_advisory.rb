require 'salus/scanners/github_advisory/base'

module Salus::Scanners::GithubAdvisory
  class GoGithubAdvisory < Base
    class SemVersion < Gem::Version; end

    def self.supported_languages
      %w[go]
    end

    def run_github_advisory_scan?
      @repository.go_mod_present? || @repository.go_sum_present?
    end

    def find_repo_dependencies
      # Find map of dependencies and versions used by the project
      dependencies = {
      }
      dependencies
    end

    def run
      results = []
      # Find dependencies from the project
      dependencies = find_repo_dependencies
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
            version_match = false
            version_ranges = m.dig("vulnerableVersionRange").split(', ')
            if version_ranges.length == 1
              version_match = SemDependency.new('', version_ranges[0]).match?('', version)
            elsif version_ranges.length == 2
              version_match = SemDependency.new('', version_ranges[0]).match?('', version) &&
                SemDependency.new('', version_ranges[1]).match?('', version)
            end
            if version_match
              results.append({
                               "Package": m.dig("package", "name"),
                  "Vulnerable Version": m.dig("vulnerableVersionRange"),
                  "Version Detected (In Project)": version,
                  "Patched Versions": m.dig("firstPatchedVersion", "identifier") || "Not Found",
                  "Summary": m.dig("advisory", "summary"),
                  "Severity": m.dig("advisory", "severity"),
                  "ID": m["advisory"]["identifiers"][0]["value"],
                  "References": m["advisory"]["references"].collect { |p| p["url"].to_s },
                  "Source": "Github Advisory"
                             })
            end
          end
        end
      end

      # Report scanner status
      if results.any?
        results.append({
                         "NOTE": "Affected packages were found using - \n" \
                         "1. 'go mod graph' results OR" \
                         "\n2. 'go.sum' file." \
                       })
        log(format_vulns(results))
        report_failure
      else
        report_success
      end
    end
  end
end
