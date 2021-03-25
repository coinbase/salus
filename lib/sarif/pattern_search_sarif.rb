require 'salus/bugsnag'

module Sarif
  class PatternSearchSarif < BaseSarif
    include Salus::SalusBugsnag

    NOT_FOUND = "Required Pattern Not Found".freeze
    PATTERN_SEARCH_URI = "https://github.com/coinbase/salus/blob/master/docs/scanners/"\
    "pattern_search.md".freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = PATTERN_SEARCH_URI
      @logs = parse_scan_report!
    end

    def parse_scan_report!
      scan_hash = @scan_report.to_h
      hits = scan_hash.dig(:info, :hits)
      misses = scan_hash.dig(:info, :misses)
      hits.concat(misses)
    end

    def build_result(parsed_issue)
      result = super
      uri = result[:locations][0][:physicalLocation][:artifactLocation][:uri]
      result[:locations] = [] if uri.nil?
      result
    end

    def build_rule(parsed_issue)
      rule = super
      return if rule.nil?

      rule[:fullDescription][:text] = NOT_FOUND if rule[:id] == NOT_FOUND
      rule
    end

    def message(hit, miss)
      pattern = hit[:regex]
      msg = hit[:msg]
      config = hit[:config]
      if !miss
        return "#{msg}. Pattern #{pattern} is forbidden." if !pattern.nil? && !msg.nil?
        return "Pattern #{pattern} is forbidden" if !pattern.nil?
        return "#{msg}. Pattern in #{config} is forbidden." if !config.nil? && !msg.nil?
        return "Pattern in #{config} is forbidden." if !config.nil?

        "Forbidden Pattern Found"
      else
        return "#{msg}.Pattern #{pattern} is required but not found." if !pattern.nil? && !msg.nil?
        return "Pattern #{pattern} is required but not found." if !pattern.nil?
        return "#{msg}. Pattern in #{config} is required but not found."\
        if !config.nil? && !msg.nil?
        return "Pattern in #{config} is required but not found." if !config.nil?

        "Required Pattern Not Found"
      end
    end

    def parse_miss(miss)
      return nil if miss[:msg].nil?
      return nil if miss[:msg].include?("Required")
      return nil if @issues.include?(miss[:msg])

      @issues.add(miss[:msg])
      {
        id: "Required Pattern Not Found",
        name: "Required Pattern Not Found",
        level: "HIGH",
        details: message(miss, true),
        help_url: "https://semgrep.dev/docs/writing-rules/rule-syntax/"
      }
    end

    def parse_issue(issue)
      return nil if issue.nil?
      return parse_miss(issue) if !issue.key?(:hit)
      return nil if !issue[:forbidden]

      url_info = issue[:hit].split(':')
      id = issue[:regex] + ' ' + issue[:hit] # [filename, line, message]
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: "Forbidden Pattern Found",
        name: "Forbidden Pattern Found",
        level: "HIGH",
        details: message(issue, false),
        start_line: url_info[1],
        start_column: 1,
        uri: url_info[0],
        help_url: PATTERN_SEARCH_URI,
        code: issue[:hit]
      }
    end
  end
end
