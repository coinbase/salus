require 'salus/bugsnag'

module Sarif
  class SemgrepSarif < BaseSarif
    include Salus::SalusBugsnag

    SEMGREP_URI = 'https://semgrep.dev/'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = SEMGREP_URI
      @logs = parse_scan_report!
      @issues = Set.new
    end

    def parse_scan_report!
      hits = @scan_report.to_h.dig(:info, :hits)
      warnings = @scan_report.to_h.dig(:warn, :semgrep_non_fatal) || []
      hits.concat(warnings)
    end

    def parse_issue(issue)
      if issue.key?(:type)
        parse_warning(issue)
      else
        parse_hit(issue)
      end
    end

    def parse_hit(hit)
      id = hit[:pattern] || hit[:msg]
      return nil if @issues.include?(id)

      @issues.add(id)
      location = hit[:hit].split(":") # [file_name, line, code_preview]
      {
        id: id,
        name: "#{id} / #{hit[:msg]}",
        level: "HIGH",
        details: "Pattern: #{hit[:pattern]}\nMessage:#{hit[:msg]}\nForbidden:#{hit[:forbidden]}"\
        "\nRequired:#{hit[:required]}\nHit: #{hit[:hit]}",
        start_line: location[1],
        start_column: 1,
        uri: location[0],
        help_url: "https://semgrep.dev/docs/writing-rules/rule-syntax/",
        code: location[2],
        rule: "Pattern: #{hit[:pattern]}\nMessage: #{hit[:msg]}"
      }
    end

    def parse_warning(warning)
      return nil if @issues.include?(warning[:type])

      @issues.add(warning[:type])
      {
        id: warning[:type],
        name: warning[:type],
        level: warning[:level],
        details: warning[:message],
        start_line: warning[:spans][0][:start]["line"],
        start_column: warning[:spans][0][:start]["col"],
        uri: warning[:spans][0][:file],
        help_url: "https://semgrep.dev/docs/writing-rules/rule-syntax/"
      }
    end

    def sarif_level(severity)
      result = super(severity)
      case severity
      when "warning"
        SARIF_WARNINGS[:warning]
      when "warn"
        SARIF_WARNINGS[:warning]
      else
        result
      end
    end

    # one hit should not define the description of a rule for all other hits
    def build_rule(parsed_issue)
      rule = super
      rule[:fullDescription][:text] = parsed_issue[:rule] if parsed_issue.key?(:rule)
      rule
    end
  end
end
