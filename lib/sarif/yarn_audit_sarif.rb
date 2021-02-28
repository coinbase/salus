require 'salus/bugsnag'
module Sarif
  include Salus::SalusBugsnag
  class YarnAuditSarif < BaseSarif
    YARN_URI = 'https://classic.yarnpkg.com/en/docs/cli/audit/'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = YARN_URI
      begin
        @logs = scan_report.to_h.fetch(:logs).dump.split("\\n\\n")
      rescue KeyError => e
        bugsnag_notify(e.message)
        @logs = []
      end
      @issues = Set.new
    end

    def parse_issue(issue)
      parsed_issue = issue.split('\\n')
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

      id = h['ID']
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: format('YARN%<number>.4d', number: h['ID'].to_i),
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

    def sarif_level(severity)
      case severity
      when "LOW"
        "note"
      when "MODERATE"
        "warning"
      when "HIGH"
        "error"
      when "INFO"
        "note"
      when "CRITICAL"
        "error"
      else
        "note"
      end
    end
  end
end
