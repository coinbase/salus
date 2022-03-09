require 'salus/scanners/osv/base'

module Salus::Scanners::OSV
  class PythonOSV < Base
    class SemDependency < Gem::Dependency; end

    EMPTY_STRING = "".freeze
    DEFAULT_SOURCE = "https://osv.dev/list".freeze
    DEFAULT_SEVERITY = "MODERATE".freeze
    GITHUB_DATABASE_STRING = "Github Advisory Database".freeze
    PYTHON_OSV_ADVISORY_URL = "https://osv-vulnerabilities.storage.googleapis.com/"\
        "PyPI/all.zip".freeze

    def should_run?
      @repository.requirements_txt_present?
    end

    def run
      dependencies = find_dependencies

      if dependencies.empty?
        err_msg = "PythonOSV: Failed to parse any dependencies from the project."
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end

      @osv_vulnerabilities ||= fetch_vulnerabilities(PYTHON_OSV_ADVISORY_URL)
      if @osv_vulnerabilities.nil?
        err_msg = "PythonOSV: No vulnerabilities found to compare."
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end

      # Report scanner status
      results = fetch_vulnerable_dependencies(dependencies)
      return report_success if results.empty?

      report_failure
      log(JSON.pretty_generate(results))
    end

    private

    # Match if dependency version found is in version list
    def version_matching(version, vulnerable_versions)
      vulnerable_flag = false
      versions = version.split(",")
      if versions.length == 1
        vulnerable_versions.each do |vulnerable_version|
          vulnerable_flag = SemDependency.new('', versions[0]).match?('', vulnerable_version)
          break if vulnerable_flag
        end
      elsif versions.length == 2
        vulnerable_versions.each do |vulnerable_version|
          vulnerable_flag = SemDependency.new('', versions[0]).match?('', vulnerable_version) &&
            SemDependency.new('', versions[1]).match?('', vulnerable_version)
          break if vulnerable_flag
        end
      end

      vulnerable_flag
    end

    # Compare vulnerabilities found with dependencies found
    # and return vulnerable dependencies
    def match_vulnerable_dependencies(dependencies)
      results = []
      dependencies.each do |lib, version|
        if version
          version = version.gsub("==", "")
          package_matches = @osv_vulnerabilities.select do |v|
            v.dig("package", "name") == lib
          end

          package_matches.each do |match|
            match["ranges"].each do |version_ranges|
              introduced, fixed = vulnerability_info_for(version_ranges)
              if %w[SEMVER ECOSYSTEM].include?(version_ranges["type"]) &&
                  version_matching(version, match.fetch("versions", []))
                results.append(vulnerability_document(match, version, introduced, fixed))
              end
            end
          end
        end
      end
      results
    end

    def vulnerability_info_for(version_range)
      introduced = version_range["events"]&.first&.[]("introduced")
      fixed = version_range["events"]&.[](1)&.[]("fixed")
      [introduced.nil? ? EMPTY_STRING : introduced, fixed.nil? ? EMPTY_STRING : fixed]
    end

    def vulnerability_document(match, version, introduced, fixed)
      {
        "Package": match.dig("package", "name"),
        "Vulnerable Version": introduced,
        "Version Detected": version,
        "Patched Version": fixed,
        "ID": match.fetch("aliases", [match.fetch("id", [])])[0],
        "Database": match.fetch("database"),
        "Summary": match.fetch("summary", match.dig("details")).strip,
        "References": match.fetch("references", []).collect do |p|
                        p["url"]
                      end.join(", "),
        "Source":  match.dig("database_specific", "url") || DEFAULT_SOURCE,
        "Severity": match.dig("database_specific",
                              "severity") || DEFAULT_SEVERITY
      }
    end

    # Fetch and Dedupe / Select Github Advisory over other sources when available.
    def fetch_vulnerable_dependencies(dependencies)
      results = []
      grouped = match_vulnerable_dependencies(dependencies).group_by { |d| d[:ID] }
      grouped.each do |_key, values|
        vuln = {}
        values.each do |v|
          vuln = v if v[:Database] == GITHUB_DATABASE_STRING
        end
        results.append(vuln.empty? ? values[0] : vuln)
      end
      results
    end

    # Find dependencies from the project
    def find_dependencies
      dependencies = {}

      shell_return = run_shell(['bin/report_python_modules',
                                @repository.path_to_repo], chdir: nil)
      if !shell_return.success?
        report_error(shell_return.stderr)
        return {}
      end

      begin
        dependencies = JSON.parse(shell_return.stdout)
      rescue JSON::ParserError
        err_msg = "PythonOSV: Could not parse JSON returned by bin/report_python_modules's stdout"
        report_stderr(err_msg)
        report_error(err_msg)
        return {}
      end

      dependencies
    end
  end
end
