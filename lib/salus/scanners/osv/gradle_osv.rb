require 'salus/scanners/osv/base'

module Salus::Scanners::OSV
  class GradleOSV < Base
    class SemVersion < Gem::Version; end

    EMPTY_STRING = "Not Found".freeze
    DEFAULT_SOURCE = "https://osv.dev/list".freeze
    DEFAULT_SEVERITY = "MODERATE".freeze
    GITHUB_DATABASE_STRING = "Github Advisory Database".freeze
    GRADLE_OSV_ADVISORY_URL = "https://osv-vulnerabilities.storage.googleapis.com"\
        "/Maven/all.zip".freeze

    def should_run?
      @repository.build_gradle_present?
    end

    def run
      dependencies = find_dependencies
      if dependencies.nil?
        err_msg = "GradleOSV: Failed to parse any dependencies from the project."
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end

      @osv_vulnerabilities ||= fetch_vulnerabilities(GRADLE_OSV_ADVISORY_URL)
      if @osv_vulnerabilities.nil?
        err_msg = "No vulnerabilities found to compare."
        bugsnag_notify("GradleOSV: #{err_msg}")
        return report_error("GradleOSV: #{err_msg}")
      end

      # Match vulnerable dependencies.
      # Dedupe and select Github Advisory over other sources if available.
      results = []
      grouped = match_vulnerable_dependencies(dependencies).group_by { |d| d[:ID] }
      grouped.each do |_key, values|
        vuln = {}
        values.each do |v|
          vuln = v if v[:Database] == GITHUB_DATABASE_STRING
        end
        results.append(vuln.empty? ? values[0] : vuln)
      end
      # Report scanner status
      return report_success if results.empty?

      report_failure
      log(JSON.pretty_generate(results))
    end

    # Match if dependency version found is in the range of
    # vulnerable dependency found.
    def version_matching(version, version_ranges)
      vulnerable_flag = false

      begin
        version = version.delete("^0-9.")
        version = version.gsub(/\.+$/, "")
        version_found = SemVersion.new(version)
      rescue StandardError
        bugsnag_notify("GradleOSV: Version #{version} is of incompatible format.")
        vulnerable_flag
      end

      # If version range length is 1, then no fix available.
      if version_ranges.length == 1
        introduced = SemVersion.new(
          version_ranges[0]["introduced"]
        )
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
      vulnerable_flag
    end

    # Compare vulnerabilities found with dependencies found
    # and return vulnerable dependencies
    def match_vulnerable_dependencies(dependencies)
      results = []
      dependencies.each do |dependency|
        lib = "#{dependency['group_id']}:#{dependency['artifact_id']}"

        unless dependency['version'].nil?
          # Cleanup version string.
          package_matches = @osv_vulnerabilities.select do |v|
            v.dig("package", "name") == lib
          end

          package_matches.each do |m|
            m["ranges"].each do |version_ranges|
              if version_ranges["type"] == "SEMVER" || version_ranges["type"] == "ECOSYSTEM"
                introduced = version_ranges["events"][0]["introduced"]
                fixed = if version_ranges["events"].length == 2
                          version_ranges["events"][1]["fixed"]
                        else
                          EMPTY_STRING
                        end
                if version_matching(dependency["version"], version_ranges["events"])
                  results.append({
                                   "Package": m.dig("package", "name"),
                    "Vulnerable Version": introduced,
                    "Version Detected": dependency["version"],
                    "Patched Version": fixed,
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
          end
        end
      end
      results
    end

    # Find dependencies from the project
    def find_dependencies
      shell_return = run_shell("/home/bin/parse_gradle_deps")
      if !shell_return.success?
        report_error(shell_return.stderr)
        return
      end

      begin
        dependencies = JSON.parse(shell_return.stdout)
      rescue JSON::ParserError
        return
      end

      # Dedupe dependencies to avoid listing duplicated.
      uniques = []
      dependencies.group_by { |e| [e["group_id"], e["artifact_id"]] }.each do |_key, values|
        uniques.append(values[0])
      end

      uniques
    end
  end
end
