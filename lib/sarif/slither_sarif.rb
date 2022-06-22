require 'salus/bugsnag'

module Sarif
  ##
  # Class for slither security scanner
  #
  class SlitherSarif < BaseSarif
    include Salus::SalusBugsnag
    SLITHER_URI = 'https://github.com/crytic/slither'.freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = SLITHER_URI
      @logs = parse_scan_report!
    end

    def parse_scan_report!
      logs = @scan_report.log('')
      return [] if logs.strip.empty?

      JSON.parse(logs)
    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      []
    end

    ##
    # Parses a single vulnerability output from slither
    # @params [issue] given vulnerability to be parsed
    # @returns [String] a hash that matches the specification for SARIF
    #
    def parse_issue(issue)
      parsed_issue = {
        id: issue['check'],
        name: issue['check'],
        level: issue['impact'].upcase,
        details: issue['description'],
        properties: { confidence: issue['confidence'] },
        uri: issue['location'],
        help_url: issue['ref_url']
      }

      # the slither location field is in the format:
      # contracts/FileName.sol#L62-L76
      line_number = issue['location'].scan(/#L[0-9]*/).first
      return parsed_issue if line_number.nil?

      line_number.slice!('#L')
      line_number = line_number.to_i
      if line_number != 0
        parsed_issue[:start_line] = line_number
        parsed_issue[:start_column] = 1
      end
      parsed_issue
    end
  end
end
