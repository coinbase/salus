require 'salus/bugsnag'

module Sarif
  class PatternSearchSarif < BaseSarif
    include Salus::SalusBugsnag

    NOT_FOUND = "Required Pattern Not Found".freeze
    PATTERN_SEARCH_URI = "https://github.com/coinbase/salus/blob/master/docs/scanners/"\
    "pattern_search.md".freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
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

      if !miss
        return "#{msg}. Pattern #{pattern} is forbidden." if pattern != "" && msg != ""
        return "Pattern #{pattern} is forbidden" if !pattern != ""
        return "#{msg}. is forbidden." if !msg != ""

        "Forbidden Pattern Found"
      else
        return "#{msg}. Pattern #{pattern} is required but not found." if pattern != "" && msg != ""
        return "Pattern #{pattern} is required but not found." if pattern != ""
        return "#{msg}. is required but not found." if msg != ""

        "Required Pattern Not Found"
      end
    end

    def parse_miss(miss)
      {
        id: "Required Pattern Not Found",
       name: "Required Pattern Not Found",
       level: "HIGH",
       details: message(miss, true),
       help_url: PATTERN_SEARCH_URI
      }
    end

    def parse_issue(issue)
      return nil if issue.nil?
      return parse_miss(issue) if !issue.key?(:hit)
      return nil if issue[:required]
      return nil if !issue[:forbidden]

      url_info = issue[:hit].split(':')

      {
        id: "Forbidden Pattern Found",
        name: "Forbidden Pattern Found",
        level: "HIGH",
        details: message(issue, false),
        start_line: url_info[1],
        start_column: 1,
        uri: url_info[0],
        help_url: PATTERN_SEARCH_URI,
        code: issue[:hit],
        properties: { severity: "HIGH" }
      }
    end

    def self.snippet_possibly_in_git_diff?(snippet, lines_added)
      lines = snippet.split("\n")
      lines.all? do |line|
        line = line.split(':', 3)[2]
        if line.nil?
          true
        else
          lines_added.keys.include?(line)
        end
      end
    end
  end
end
