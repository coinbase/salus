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
      logs = build_logs(scan_hash.dig(:logs))
      hits.concat(logs)
    end

    def build_logs(log)
      return [] if log.nil?

      logs = log.split("Required")
      result = []
      logs.each do |message|
        if message.include? " pattern"
          parsed = {
            msg: message,
            required: true
          }
          result << parsed
        end
      end
      result
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

    def parse_issue(issue)
      return nil if issue.nil?
      return parse_log(issue) if !issue.key?(:hit)

      url_info = issue[:hit].split(':')
      id = issue[:regex] + ' ' + issue[:hit] # [filename, line, message]
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: id(issue[:forbidden], issue[:required]),
        name: "Regex: #{issue[:regex]}",
        level: "HIGH",
        details: "Regex: #{issue[:regex]}\nForbidden: #{issue[:forbidden]}\nMessage:#{issue[:msg]}"\
        "\nRequired: #{issue[:required]}",
        start_line: url_info[1],
        start_column: 1,
        uri: url_info[0],
        help_url: PATTERN_SEARCH_URI,
        code: issue[:hit]
      }
    end

    def id(forbidden, required)
      return 'Forbidden pattern found / Required pattern found' if forbidden & required
      return 'Forbidden pattern found' if forbidden
      return 'Required pattern found' if required
    end
  end
end
