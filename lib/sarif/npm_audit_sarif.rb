module Sarif
  class NPMAuditSarif < BaseSarif
    NPM_URI = 'https://docs.npmjs.com/cli/v7/commands/npm-audit'.freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = NPM_URI
      @logs = parse_scan_report!
      @exceptions = Set.new(@scan_report.to_h.dig(:info, :exceptions))
      @results = []
    end

    def parse_scan_report!
      log = @scan_report.to_h.dig(:info, :stdout, :advisories)
      return [] if log.nil?

      log.values
    end

    def parse_issue(issue)
      id = issue[:id].to_s
      return nil if @issues.include?(id) || @exceptions.include?(id)

      @results.push(id) if !@exceptions.include?(id)
      @issues.add(id)

      parsed_issue = {
        id: id,
        name: issue[:title],
        level: issue[:severity].upcase,
        details: (issue[:overview]).to_s,
        messageStrings: { "package": { "text": (issue[:module_name]).to_s },
                         "severity": { "text": (issue[:severity]).to_s },
                         "patched_versions": { "text": (issue[:patched_versions]).to_s },
                         "cwe": { "text": (issue[:cwe]).to_s },
                         "recommendation": { "text": (issue[:recommendation]).to_s },
                         "vulnerable_versions": { "text": (issue[:vulnerable_versions]).to_s } },
        properties: { 'severity': (issue[:severity]).to_s },
        uri: "package-lock.json",
        help_url: issue[:url],
        suppressed: @exceptions.include?(id)
      }

      if issue[:line_number]
        parsed_issue[:start_line] = issue[:line_number]
        parsed_issue[:start_column] = 1
        parsed_issue[:code] = issue[:module_name].to_s
      end

      parsed_issue
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

    def build_invocations(scan_report, supported)
      invocation = super(scan_report, supported)
      invocation[:executionSuccessful] = @results.empty?
      invocation
    end

    def self.snippet_possibly_in_git_diff?(snippet, lines_added)
      snippet = "\"" + snippet + "\":"
      lines_added.keys.any? { |k| k.include? snippet }
    end
  end
end
