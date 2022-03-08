require 'salus/scanners/osv/base'

module Salus::Scanners::OSV
  class MavenOSV < Base
    class SemVersion < Gem::Version; end

    EMPTY_STRING = "".freeze
    DEFAULT_SOURCE = "https://osv.dev/list".freeze
    DEFAULT_SEVERITY = "MODERATE".freeze
    GITHUB_DATABASE_STRING = "Github Advisory Database".freeze
    MAVEN_OSV_ADVISORY_URL = "https://osv-vulnerabilities.storage.googleapis.com/"\
        "Maven/all.zip".freeze

    def should_run?
      @repository.pom_xml_present?
    end

    def run
      begin
        parser = Salus::MavenDependencyParser.new(@repository.pom_xml_path)
        parser.parse
        if parser.pom_xml_dependencies.empty?
          err_msg = "MavenOSV: Failed to parse any dependencies from the project."
          raise StandardError, err_msg
        end
      rescue StandardError => e
        report_stderr(e.message)
        report_error(e.message)
        return
      end

      @osv_vulnerabilities ||= fetch_vulnerabilities(MAVEN_OSV_ADVISORY_URL)
      if @osv_vulnerabilities.nil?
        err_msg = "MavenOSV: No vulnerabilities found to compare."
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end

      # Report scanner status
      results = fetch_vulnerable_dependencies(parser.pom_xml_dependencies)
      return report_success if results.empty?

      report_failure
      log(JSON.pretty_generate(results))
    end

    private

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
        lib = "#{dependency.fetch('group_id', '')}:#{dependency.fetch('artifact_id', '')}"
        if dependency['version']
          version = dependency['version']
          # If version is of the format '${deps.version}', log it.
          if version.match(/\${(.*)\.version}/)
            bugsnag_notify("MavenOSV: Found #{lib}:#{version} with incompatible format.")
            next
          end

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
            #   "severity"=>"MODERATE"}, "id"=>"GHSA-xxxx-xxxx-xxxx",
            #   "summary"=>"Privilege escalation in sample-java",
            #   "details"=>"Vulnerability in the Sample Java.", "aliases"=>["CVE-0000-0000"],
            #   "modified"=>"2022-00-00T00:00:00.00Z", "published"=>"2020-00-00T00:00:00Z",
            #   "references"=>[{"type"=>"ADVISORY",
            #   "url"=>"https://nvd.nist.gov/vuln/detail/CVE-0000-0000"}],
            #   "schema_version"=>"1.2.0", "severity"=>[{"type"=>"CVSS_V3",
            #   "score"=>"CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H"}]
            #   "database"=>"Github Advisory Database"
            # }
            match["ranges"].each do |version_ranges|
              introduced, fixed = vulnerability_info_for(version_ranges)
              if %w[SEMVER ECOSYSTEM].include?(version_ranges["type"])
                if version_matching(version, introduced, fixed)
                  results.append({
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
                                 })
                end
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
  end
end
