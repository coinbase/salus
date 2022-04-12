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
      # Find dependencies
      begin
        parser = Salus::PythonDependencyParser.new(@repository.path_to_repo)
        parser.parse
        if parser.requirements_txt_dependencies.empty?
          err_msg = "PythonOSV: Failed to parse any dependencies from the project."
          raise StandardError, err_msg
        end
      rescue StandardError => e
        report_stderr(e.message)
        report_error(e.message)
        return
      end

      # Fetch vulnerabilities
      @osv_vulnerabilities ||= fetch_vulnerabilities(PYTHON_OSV_ADVISORY_URL)
      if @osv_vulnerabilities.nil?
        err_msg = "PythonOSV: No vulnerabilities found to compare."
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

    # Match if dependency version found is in version list
    def version_matching(version, vulnerable_versions)
      vulnerable_flag = false
      vulnerable_versions.each do |vulnerable_version|
        status = version.split(",").collect do |each|
          SemDependency.new('', each).match?('', vulnerable_version)
        end
        vulnerable_flag = status.all?
        break if vulnerable_flag
      end

      vulnerable_flag
    end

    # Compare vulnerabilities found with dependencies found
    # and return vulnerable dependencies
    def match_vulnerable_dependencies(dependencies)
      results = []
      dependencies.each do |lib, version|
        if version.present?
          version = version.gsub("==", "")
          package_matches = @osv_vulnerabilities.select do |v|
            v.dig("package", "name") == lib
          end

          package_matches.each do |match|
            # 'match' sample
            # {
            #   "package"=>{"name"=>"sample", "ecosystem"=>"PyPI", "purl"=>"pkg:pypi/sample"},
            #   "ranges"=>[{"type"=>"ECOSYSTEM", "events"=>[{"introduced"=>"0"},
            #   {"fixed"=>"2.3.0"}]}], "versions"=>["0.0.1", "0.10.0", "0.10.1"],
            #   "database_specific"=>{"source"=>"https://github.com/pypa/"},
            #   "id"=>"PYSEC-XX-XX", "details"=>"Requests..", "aliases"=>["CVE-XX-XX"],
            #   "modified"=>"2021-00-00T00:00:00.001Z", "published"=>"2014-00-00T00:00:00Z",
            #   "references"=>[{"type"=>"WEB", "url"=>"https://bugs.debian.org"}],
            #   "schema_version"=>"1.2.0", "database"=>"Python Packaging Advisory Database"
            # }
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
  end
end
