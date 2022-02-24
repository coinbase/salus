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

    def find_dependencies
      # Return a map of dependency name and versions used by the project
      all_dependencies = []
      chosen_dependencies = {}

      go_sum_path = "#{@repository.path_to_repo}/go.sum"
      File.foreach(go_sum_path).each("=\n") do |line|
        line = line.strip
        next if line.empty?

        parts = line.split
        if parts.length > 2
          name = parts[0]
          version = parts[1]
          version.slice!(0) if version[0] == 'v'
          all_dependencies.append({
                                    "name": name,
                                    "version": version.to_s.gsub('/go.mod', '')
                                    .gsub('+incompatible', '')
                                  })
        end
      end

      # Pick specific version of dependencies
      # If multiple versions of dependencies are found then pick the max version to mimic MVS
      # https://go.dev/ref/mod#minimal-version-selection
      all_dependencies.each do |deps|
        lib = deps[:name]
        version = deps[:version].to_s.gsub('v', '').gsub('+incompatible', '')
        if chosen_dependencies.key?(lib)
          chosen_dependencies[lib] = version if SemVersion.new(version) >
            SemVersion.new(chosen_dependencies[lib])
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
        bugsnag_notify("GoOSV: #{msg}")
        return report_error("GoOSV: #{msg}")
      end

      # Match dependencies found with advisories from Github
      if osv_vulnerabilities.nil?
        msg = "No vulnerabilities found to compare."
        bugsnag_notify("GoOSV: #{msg}")
        return report_error("GoOSV: #{msg}")
      else
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
                version_ranges[0]["introduced"].to_s.gsub('v', '').gsub('+incompatible', '')
              )
              version_found = SemVersion.new(version)
              vulnerable_flag = true if version_found >= introduced
            # If version range length is 2, then both introduced and fixed are available.
            elsif version_ranges.length == 2
              introduced = SemVersion.new(
                version_ranges[0]["introduced"].to_s.gsub('v', '').gsub('+incompatible', '')
              )
              fixed = SemVersion.new(
                version_ranges[1]["fixed"].to_s.gsub('v', '').gsub('+incompatible', '')
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
                "Severity": DEFAULT_SEVERITY
                             })
            end
          end
        end
      end
      # Report scanner status
      if results.length.positive?
        report_failure
        log(format_vulns(results))
      else
        report_success
      end
    end
  end
end
