require 'salus/scanners/osv/base'

module Salus::Scanners::OSV
  class GoOSV < Base
    class SemVersion < Gem::Version; end
    class SemDependency < Gem::Dependency; end

    EMPTY_STRING = "Not Found".freeze
    DEFAULT_SOURCE = "https://osv.dev/list".freeze
    DEFAULT_SEVERITY = "LOW".freeze

    def should_run?
      @repository.go_sum_present?
    end

    def run
      dependencies = find_dependencies
      if dependencies.empty?
        msg = "Failed to parse any dependencies from the project."
        bugsnag_notify("GoOSV: #{msg}")
        return report_error("GoOSV: #{msg}")
      end

      results = []
      if osv_vulnerabilities.nil?
        msg = "No vulnerabilities found to compare."
        bugsnag_notify("GoOSV: #{msg}")
        return report_error("GoOSV: #{msg}")
      else
        results = match_vulnerable_dependencies(dependencies)
      end
      # Report scanner status
      return report_success if results.empty?

      report_failure
      log(format_vulns(results))
    end

    # Find dependencies from the project
    def find_dependencies
      # Return a map of dependency name and versions used by the project
      shell_return = run_shell("bin/parse_go_sum #{@repository.go_sum_path}", chdir: nil)

      if !shell_return.success?
        report_error(shell_return.stderr)
        return
      end

      all_dependencies = nil
      begin
        all_dependencies = JSON.parse(shell_return.stdout)
      rescue JSON::ParserError
        err_msg = "Could not parse JSON returned by bin/parse_go_sum's stdout!"
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end

      dependencies = {}
      # Pick specific version of dependencies
      # If multiple versions of dependencies are found then pick the max version to mimic MVS
      # https://go.dev/ref/mod#minimal-version-selection
      all_dependencies.each do |dependency|
        lib = dependency["namespace"] + "/" + dependency["name"]
        version = dependency["version"].to_s.gsub('v', '').gsub('+incompatible', '')
        if dependencies.key?(lib)
          dependencies[lib] = version if SemVersion.new(version) >
            SemVersion.new(dependencies[lib])
        else
          dependencies[lib] = version
        end
      end
      dependencies
    end

    # Compare vulnerabilities found with dependencies found
    # and return vulnerable dependencies
    def match_vulnerable_dependencies(dependencies)
      results = []
      dependencies.each do |lib, version|
        package_matches = osv_vulnerabilities.select do |v|
          v.dig("package", "name") == lib
        end

        package_matches.each do |m|
          version_ranges = m["ranges"][0]["events"]
          version_found = SemVersion.new(version)
          vulnerable_flag = false
          # If version range length is 1, then no fix available.
          if version_ranges.length == 1
            introduced = SemVersion.new(
              version_ranges[0]["introduced"]
            )
            version_found = SemVersion.new(version)
            vulnerable_flag = true if version_found >= introduced
          # If version range length is 2, then both introduced and fixed are available.
          elsif version_ranges.length == 2
            introduced = SemVersion.new(
              version_ranges[0]["introduced"]
            )
            fixed = SemVersion.new(
              version_ranges[1]["fixed"]
            )
            vulnerable_flag = true if version_found >= introduced && version_found < fixed
          end

          if vulnerable_flag
            results.append({
                             "Package": m.dig("package", "name"),
              "Vulnerable Version": version_ranges[0]["introduced"],
              "Version Detected": version_found,
              "Patched Version": fixed || EMPTY_STRING,
              "ID": m.fetch("aliases", [m.fetch("id", [])])[0],
              "Summary": m.fetch("summary", m.dig("details")).strip,
              "References": m.fetch("references", []).collect do |p|
                              p["url"]
                            end.join(", "),
              "Source":  m.dig("database_specific", "url") || DEFAULT_SOURCE,
              "Severity": m.dig("database_specific", "severity") || DEFAULT_SEVERITY
                           })
          end
        end
      end
      results
    end
  end
end
