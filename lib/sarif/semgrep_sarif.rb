require 'salus/bugsnag'

module Sarif
  class SemgrepSarif < BaseSarif
    include Salus::SalusBugsnag

    NOT_FOUND = "Required Pattern Not Found".freeze
    SEMGREP_URI = "https://github.com/coinbase/salus/blob/master/docs/scanners/"\
                     "semgrep.md".freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = SEMGREP_URI
      @logs = parse_scan_report!
      @issues = Set.new
    end

    def build_rule(parsed_issue)
      rule = super
      return if rule.nil?

      rule[:fullDescription][:text] = NOT_FOUND if rule[:id] == NOT_FOUND
      rule
    end

    def build_result(parsed_issue)
      result = super
      uri = result[:locations][0][:physicalLocation][:artifactLocation][:uri]
      result[:locations] = [] if uri.nil?
      result
    end

    def parse_scan_report!
      scan_hash = @scan_report.to_h
      hits = scan_hash.dig(:info, :hits)
      warnings = scan_hash.dig(:warn, :semgrep_non_fatal) || []
      misses = scan_hash.dig(:info, :misses)
      hits.concat(warnings, misses)
    end

    def parse_issue(issue)
      if issue.key?(:hit)
        parse_hit(issue)
      elsif issue.key?(:type)
        parse_warning(issue)
      else
        parse_miss(issue)
      end
    end

    def message(hit, miss)
      pattern = hit[:pattern]
      msg = hit[:msg]
      config = hit[:config]
      if !miss
        return "#{msg}. Pattern #{pattern} is forbidden." if !pattern.nil? && msg != ""
        return "Pattern #{pattern} is forbidden" if !pattern.nil?
        return "#{msg}. Pattern in #{config} is forbidden." if !config.nil? && msg != ""
        return "Pattern in #{config} is forbidden." if !config.nil?

        "Forbidden Pattern Found"
      else
        return "#{msg}. Pattern #{pattern} is required but not found." if !pattern.nil? && msg != ""
        return "Pattern #{pattern} is required but not found." if !pattern.nil?
        return "#{msg}. Pattern in #{config} is required but not found."\
        if !config.nil? && msg != ""
        return "Pattern in #{config} is required but not found." if !config.nil?

        "Required Pattern Not Found"
      end
    end

    def parse_hit(hit)
      return nil if !hit[:forbidden]

      location = hit[:hit].split(":") # [file_name, line, code_preview]

      {
        id: "Forbidden Pattern Found",
        name: "#{hit[:pattern]} / #{hit[:msg]} Forbidden Pattern Found",
        level: "HIGH",
        details: message(hit, false),
        start_line: location[1],
        start_column: 1,
        uri: location[0],
        help_url: SEMGREP_URI,
        code: location[2],
        rule: "Pattern: #{hit[:pattern]}\nMessage: #{hit[:msg]}",
        properties: { 'severity': "HIGH" }
      }
    rescue StandardError => e
      bugsnag_notify(e.message)
    end

    def parse_warning(warning)
      return nil if @issues.include?(warning[:message])

      @issues.add(warning[:message])
      {
        id: warning[:type],
        name: warning[:type],
        level: "HIGH",
        details: warning[:message],
        # Default to line one if not provided as SARIF spec requires this value
        # to be > 0
        start_line: warning[:spans].empty? ? 1 : warning[:spans][0][:start]["line"],
        start_column: warning[:spans].empty? ? 1 : warning[:spans][0][:start]["col"],
        uri: warning[:spans].empty? ? "" : warning[:spans][0][:file],
        help_url: SEMGREP_URI
      }
    end

    def parse_miss(miss)
      {
        id: "Required Pattern Not Found",
        name: "Required Pattern Not Found",
        level: "HIGH",
        details: message(miss, true),
        help_url: SEMGREP_URI
      }
    end
  end
end
