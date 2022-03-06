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
      if dependencies.empty?
        err_msg = "GradleOSV: Failed to parse any dependencies from the project."
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end

      @osv_vulnerabilities ||= fetch_vulnerabilities(GRADLE_OSV_ADVISORY_URL)
      if @osv_vulnerabilities.nil?
        err_msg = "GradleOSV: No vulnerabilities found to compare."
        report_stderr(err_msg)
        report_error(err_msg)
        return
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
    def version_matching(version, introduced, fixed)
      vulnerable_flag = false
      version_found = SemVersion.new(version)

      if introduced.present? && fixed.present?
        introduced_version = SemVersion.new(introduced)
        fixed_version = SemVersion.new(fixed)
        if version_found >= introduced_version && version_found < fixed_version
          vulnerable_flag = true
        end
      elsif introduced.present?
        introduced_version = SemVersion.new(introduced)
        vulnerable_flag = true if version_found >= introduced_version
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
          version = dependency['version']
          # Cleanup version string.
          version = version.delete("^0-9.").gsub(/\.+$/, "")
          package_matches = @osv_vulnerabilities.select do |v|
            v.dig("package", "name") == lib
          end

          package_matches.each do |m|
            m["ranges"].each do |version_ranges|
              introduced = fixed = ""
              if version_ranges["events"].length == 1
                if version_ranges["events"][0].key?("introduced")
                  introduced = version_ranges["events"][0]["introduced"]
                end
              elsif version_ranges["events"].length == 2
                if version_ranges["events"][0].key?("introduced") &&
                    version_ranges["events"][1].key?("fixed")
                  introduced = version_ranges["events"][0]["introduced"]
                  fixed = version_ranges["events"][1]["fixed"]
                end
              end

              if version_ranges["type"] == "SEMVER" || version_ranges["type"] == "ECOSYSTEM"
                if version_matching(version, introduced, fixed)
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
        return []
      end

      begin
        dependencies = JSON.parse(shell_return.stdout)
      rescue JSON::ParserError
        err_msg = "GradleOSV: Could not parse JSON returned by bin/parse_gradle_deps's stdout!"
        report_stderr(err_msg)
        report_error(err_msg)
        return []
      end

      # Dedupe dependencies returned.
      uniques = []
      dependencies.group_by { |e| [e["group_id"], e["artifact_id"]] }.each do |_key, values|
        uniques.append(values[0])
      end

      uniques
    end
  end
end
