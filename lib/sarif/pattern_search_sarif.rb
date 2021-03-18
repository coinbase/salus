require 'salus/bugsnag'

module Sarif
  class PatternSearchSarif < BaseSarif
    include Salus::SalusBugsnag

    PATTERN_SEARCH_URI = "https://github.com/coinbase/salus/blob/master/docs/scanners/"\
    "pattern_search.md".freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = PATTERN_SEARCH_URI
      @logs = scan_report.to_h.dig(:info, :hits)
    end

    def parse_issue(issue)
      url_info = issue[:hit].split(':')
      id = issue[:regex] + ' ' + issue[:hit] # [filename, line, message]
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: issue[:regex],
        name: "Regex: #{issue[:regex]}",
        level: "HIGH",
        details: "Regex: #{issue[:regex]}\nForbidden: #{issue[:forbidden]}\nMessage:#{issue[:msg]}"\
        "\nRequired: #{issue[:forbidden]}",
        start_line: url_info[1],
        start_column: 0,
        uri: url_info[0],
        help_url: PATTERN_SEARCH_URI,
        code: issue[:hit]
      }
    end
  end
end
