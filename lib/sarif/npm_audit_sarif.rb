module Sarif
  class NPMAuditSarif < BaseSarif
    NPM_URI = 'https://docs.npmjs.com/cli/v7/commands/npm-audit'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = NPM_URI
      @logs = @scan_report.to_h[:info][:stdout][:advisories].values
      @issues = Set.new
    end

    def parse_issue(issue)
      id = issue[:id].to_i
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: format('NPM%<number>.4d', number: issue[:id].to_i),
        name: issue[:title],
        level: issue[:severity].upcase,
        details: "Package:#{issue[:module_name]} \nDescription:#{issue[:overview]}"\
        " \nRecommendation: #{issue[:recommendation]}\nVulnerable Versions:"\
        " #{issue[:vulnerable_versions]} \nSeverity:#{issue[:severity]} \nPatched Versions:"\
        " #{issue[:patched_versions]}\nCWE: #{issue[:cwe]} ",
        uri: "package-lock.json",
        help_url: issue[:url]
      }
    end

    def build_invocations
      { "executionSuccessful": @scan_report.passed? }
    end

    def sarif_level(severity)
      case severity
      when "LOW"
        SARIF_WARNINGS[:note]
      when "MODERATE"
        SARIF_WARNINGS[:warning]
      when "HIGH"
        SARIF_WARNINGS[:error]
      when "CRITICAL"
        SARIF_WARNINGS[:error]
      else
        SARIF_WARNINGS[:note]
      end
    end
  end
end
