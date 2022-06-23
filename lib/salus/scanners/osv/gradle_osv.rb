require 'salus/scanners/osv/base'

module Salus::Scanners::OSV
  class GradleOSV < Base
    class SemVersion < Gem::Version; end
    include Gradle

    EMPTY_STRING = "".freeze
    DEFAULT_SOURCE = "https://osv.dev/list".freeze
    DEFAULT_SEVERITY = "MODERATE".freeze
    GRADLE_OSV_ADVISORY_URL = "https://osv-vulnerabilities.storage.googleapis.com"\
        "/Maven/all.zip".freeze

    def should_run?
      @repository.build_gradle_present?
    end

    def self.supported_languages
      ['java']
    end

    def run
      # Find dependencies from the project
      dependencies = gradle_dependencies

      if dependencies.empty?
        err_msg = "GradleOSV: Failed to parse any dependencies from the project."
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end

      # Fetch vulnerabilities
      @osv_vulnerabilities ||= fetch_vulnerabilities(GRADLE_OSV_ADVISORY_URL)
      if @osv_vulnerabilities.nil?
        err_msg = "GradleOSV: No vulnerabilities found to compare."
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end

      # Match and Report scanner status
      vulnerabilities_found = match_vulnerable_dependencies(dependencies)
      results = group_vulnerable_dependencies(vulnerabilities_found)
      return report_success if results.empty?

      report_failure
      log(JSON.pretty_generate(results))
    end

    private

    # Match if dependency version found is in the range of
    # vulnerable dependency found.
    def version_matching(version, introduced, fixed)
      vulnerable_flag = false
      if introduced.present? && fixed.present?
        if SemVersion.new(version) >= SemVersion.new(introduced) &&
            SemVersion.new(version) < SemVersion.new(fixed)
          vulnerable_flag = true
        end
      elsif introduced.present?
        vulnerable_flag = true if SemVersion.new(version) >= SemVersion.new(introduced)
      end

      vulnerable_flag
    end

    # Compare vulnerabilities found with dependencies found
    # and return vulnerable dependencies
    def match_vulnerable_dependencies(dependencies)
      results = []
      dependencies.each do |dependency|
        lib = "#{dependency['group_id']}:#{dependency['artifact_id']}"

        if dependency['version'].present?
          version = dependency['version']
          # Cleanup version string to handle case like -
          # Dynamic resolved version: dependency.xx.xx:1.1.1 -> 1.5.0
          # Version strings: 1.2.1.somestring / 9999.0-empty-to-avoid-conflict-with-test /
          # Version strings: 30.3.0-deprecated-use-gradle-api
          version = version.split("->").last.strip if version.include? "->"
          version = version.delete("^0-9.").gsub(/\.+$/, "")
          package_matches = @osv_vulnerabilities.select do |v|
            v.dig("package", "name") == lib
          end

          package_matches.each do |match|
            # 'match' format
            # {
            #   "package"=>{"name"=>"sample:sample-java", "ecosystem"=>"Maven",
            #   "purl"=>"pkg:maven/sample/sample-java"},
            #   "ranges"=>[{"type"=>"ECOSYSTEM", "events"=>[{"introduced"=>"0"},
            #   {"fixed"=>"8.0.16"}]}], "versions"=>["2.0.14", "3.0.10"],
            #   "database_specific"=>{"cwe_ids"=>["CWE-000"], "github_reviewed"=>true,
            #   "severity"=>"MODERATE"}, "id"=>"GHSA-xxxx",
            #   "summary"=>"Privilege escalation", "details"=>"Vulnerability",
            #   "aliases"=>["CVE-0000"], "modified"=>"2022-00-00T00:00:00.00Z",
            #   "published"=>"2020-00-00T00:00:00Z", "references"=>[{"type"=>"ADVISORY",
            #   "url"=>"https://nvd.nist.gov/vuln/detail/CVE-0000-0000"}],
            #   "schema_version"=>"1.2.0", "severity"=>[{"type"=>"CVSS_V3",
            #   "score"=>"CVSS:3.0"}], "database"=>"Github Advisory Database"
            # }
            match["ranges"].each do |version_ranges|
              introduced, fixed = vulnerability_info_for(version_ranges)
              if %w[SEMVER ECOSYSTEM].include?(version_ranges["type"]) &&
                  version_matching(version, introduced, fixed)
                results.append(format_vulnerability_result(match, version, introduced, fixed))
              end
            end
          end
        end
      end
      results
    end

    def format_vulnerability_result(match, version, introduced, fixed)
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

    def vulnerability_info_for(version_range)
      introduced = version_range["events"]&.first&.[]("introduced")
      fixed = version_range["events"]&.[](1)&.[]("fixed")
      [introduced.nil? ? EMPTY_STRING : introduced, fixed.nil? ? EMPTY_STRING : fixed]
    end
  end
end
