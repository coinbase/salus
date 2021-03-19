require 'salus/bugsnag'

module Sarif
  class SemgrepSarif < BaseSarif
    include Salus::SalusBugsnag

    SEMGREP_URI = 'https://semgrep.dev/'.freeze
    NOT_FOUND = "Required Pattern Not Found".freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = SEMGREP_URI
      @logs = parse_scan_report!
      @issues = Set.new
    end

    def build_logs(log)
      # add required pattern to report
      logs = log.split('Required')
      result = []
      logs.each do |message|
        if message.include? "pattern"
          parsed = {
            msg: message,
            required: true
          }
          result << parsed
        end
      end
      result
    end

    def build_rule(parsed_issue)
      rule = super
      return if rule.nil?

      rule[:fullDescription][:text] = NOT_FOUND if rule[:id] == NOT_FOUND
      rule
    end

    def parse_log(log)
      id = log[:msg]
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: NOT_FOUND,
        name: NOT_FOUND,
        level: "HIGH",
        details: log[:msg],
        help_url: "https://semgrep.dev/docs/writing-rules/rule-syntax/",
        uri: ''
      }
    end

    def parse_scan_report!
      scan_hash = @scan_report.to_h
      hits = scan_hash.dig(:info, :hits)
      warnings = scan_hash.dig(:warn, :semgrep_non_fatal) || []
      logs = build_logs(scan_hash.dig(:logs))
      hits.concat(warnings, logs)
    end

    def parse_issue(issue)
      if issue.key?(:type)
        parse_warning(issue)
      elsif issue.key?(:hit)
        parse_hit(issue)
      else
        parse_log(issue)
      end
    end

    def parse_hit(hit)
      id = hit[:hit] || hit[:msg]
      return nil if @issues.include?(id)

      @issues.add(id)
      location = hit[:hit].split(":") # [file_name, line, code_preview]
      details = "Pattern: #{hit[:pattern]}\nMessage:#{hit[:msg]}\n"
      details << "\nForbidden:#{hit[:forbidden]}" if hit[:forbidden]
      details << "\nRequired:#{hit[:required]}" if hit[:required]
      {
        id: hit[:pattern] || hit[:msg] || hit[:hit],
        name: "#{hit[:pattern]} / #{hit[:msg]}",
        level: "HIGH",
        details: details,
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
  end
end
