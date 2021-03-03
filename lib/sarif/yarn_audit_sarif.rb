require 'salus/bugsnag'
module Sarif
  class YarnAuditSarif < BaseSarif
    include Salus::SalusBugsnag
    YARN_URI = 'https://classic.yarnpkg.com/en/docs/cli/audit/'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = YARN_URI
      parse_scan_report!
      @issues = Set.new
    end

    def parse_scan_report!
      @logs = @scan_report.to_h.fetch(:logs).split("\n\n")
    rescue KeyError => e
      bugsnag_notify(e.message)
      @logs = []
    end

    def parse_issue(issue)
      parsed_issue = issue.split("\n")
      index = 0
      h = {}
      parsed_issue.each do |item|
        seperator = item.index(':')
        next if !seperator

        key = item[0, seperator].delete("\"")
        h[key] = item[seperator + 1, item.size - 1].strip
        index += 1
      end
      return nil if h.empty?

      id = h['ID'] + ' ' + h['Package'] + ' ' + h['Dependency of']
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: h['ID'],
        name: h['Title'],
        level: h['Severity'].upcase,
        details: "Title: #{h['Title']}\nPackage: #{h['Package']}\nPatched in: #{h['Patched in']}"\
        "\nDependency of:#{h['Dependency of']} \nSeverity: #{h['Severity']}",
        uri: "yarn.lock",
        help_url: h['More info']
      }
    end

    def build_invocations
      error = @scan_report.to_h[:errors]
      if !error.empty?
        error = @scan_report.to_h[:errors]
        {
          "executionSuccessful": @scan_report.passed?,
          "toolExecutionNotifications": [{
            "descriptor": {
              "id": ""
            },
            "level": "error",
            "message": {
              "text": "SALUS ERRORS:\n #{JSON.pretty_generate(error)}"
            }
          }]
        }
      else
        { "executionSuccessful": @scan_report.passed? }
      end
    end

    # fullDescription on a rule should not explain a single vulnerability
    # since multiple vulnerabilites can have the same RuleID
    def build_rule(parsed_issue)
      rule = super(parsed_issue)
      return nil if rule.nil?

      rule[:fullDescription][:text] = rule[:name]
      rule
    end

    def sarif_level(severity)
      case severity
      when "LOW"
        SARIF_WARNINGS[:note]
      when "MODERATE"
        SARIF_WARNINGS[:warning]
      when "HIGH"
        SARIF_WARNINGS[:error]
      when "INFO"
        SARIF_WARNINGS[:note]
      when "CRITICAL"
        SARIF_WARNINGS[:error]
      else
        SARIF_WARNINGS[:note]
      end
    end
  end
end
