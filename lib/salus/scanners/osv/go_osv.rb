require 'salus/scanners/osv/base'

module Salus::Scanners::OSV
  class GoOSV < Base
    class SemVersion < Gem::Version; end

    EMPTY_STRING = "".freeze
    DEFAULT_SOURCE = "https://osv.dev/list".freeze
    DEFAULT_SEVERITY = "MODERATE".freeze
    GITHUB_DATABASE_STRING = "Github Advisory Database".freeze
    GO_OSV_ADVISORY_URL = "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip".freeze

    def should_run?
      @repository.go_sum_present?
    end

    def self.supported_languages
      ['go']
    end

    def run
      begin
        # Find dependencies
        parser = Salus::GoDependencyParser.new(@repository.go_sum_path)
        parser.parse
        if parser.go_dependencies["parsed"].empty?
          err_msg = "GoOSV: Failed to parse any dependencies from the project."
          raise StandardError, err_msg
        end
      rescue StandardError => e
        report_stderr(e.message)
        report_error(e.message)
        return
      end
      dependencies = parser.select_dependencies(parser.go_dependencies)

      # Fetch vulnerabilities
      @osv_vulnerabilities ||= fetch_vulnerabilities(GO_OSV_ADVISORY_URL)
      if @osv_vulnerabilities.nil?
        err_msg = "GoOSV: No vulnerabilities found to compare."
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
      dependencies.each do |lib, version|
        package_matches = @osv_vulnerabilities.select do |v|
          v.dig("package", "name") == lib
        end

        package_matches.each do |match|
          match["ranges"].each do |version_ranges|
            introduced, fixed = vulnerability_info_for(version_ranges)
            if %w[SEMVER ECOSYSTEM].include?(version_ranges["type"]) &&
                version_matching(version, introduced, fixed)
              results.append(vulnerability_document(match, version, introduced, fixed))
            end
          end
        end
      end

      results
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
