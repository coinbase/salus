module Sarif
  class NPMAuditSarif < BaseSarif
    NPM_URI = 'https://docs.npmjs.com/cli/v7/commands/npm-audit'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = NPM_URI
      @logs = parse_scan_report!
      @issues = Set.new
    end

    def parse_scan_report!
      log = @scan_report.to_h.dig(:info, :stdout, :advisories)
      return [] if log.nil?

      log.values
    end

    def parse_issue(issue)
      id = issue[:id]
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: issue[:id],
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
      error = @scan_report.to_h[:errors]
      if error
        {
          "executionSuccessful": @scan_report.passed?,
          "toolExecutionNotifications": [{
            "descriptor": {
              "id": ""
            },
            "level": "error",
            "message": {
              "text": "==== Salus Errors\n#{JSON.pretty_generate(error)}"
            }
          }]
        }
      else
        { "executionSuccessful": @scan_report.passed? }
      end
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
