module Sarif
  class BrakemanSarif < BaseSarif
    include Salus::SalusBugsnag

    BRAKEMAN_URI = 'https://github.com/presidentbeef/brakeman'.freeze

    def initialize(scan_report, repo_path = nil, scanner_config = {})
      super(scan_report, {}, repo_path)
      @uri = BRAKEMAN_URI
      @logs = parse_scan_report!
      @scanner_config = scanner_config
    end

    def parse_scan_report!
      logs = @scan_report.log('')
      return [] if logs.strip.empty?

      parsed_result = JSON.parse(logs)
      parsed_result['warnings'].concat(parsed_result['errors'])
    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      []
    end

    def parse_error(error)
      id = error['error'] + ' ' + error['location']
      return nil if @issues.include?(id)

      @issues.add(id)
      {
        id: SCANNER_ERROR,
        name: "Brakeman Error",
        level: "HIGH",
        details: error['error'],
        uri: error['location'],
        help_url: "https://github.com/coinbase/salus/blob/master/docs/salus_reports.md"
      }
    end

    def parse_issue(issue)
      # Example issue
      # {"warning_type"=>"Dangerous Eval",
      # "warning_code"=>13,
      # "fingerprint"=>"b16e1cd0d952433f80b0403b6a74aab0e98792ea015cc1b1fa5c003cbe7d56eb",
      # "check_name"=>"Evaluation",
      # "message"=>"User input in eval",
      # "file"=>"app/controllers/static_controller_controller.rb",
      # "line"=>3,
      # "link"=>"https://brakemanscanner.org/docs/warning_types/dangerous_eval/",
      # "code"=>"eval(params[:evil])",
      # "render_path"=>nil,
      # "location"=>{"type"=>"method", "class"=>"StaticControllerController", "method"=>"index"},
      # "user_input"=>"params[:evil]",
      # "confidence"=>"High",
      # "cwe_id"=>[913, 95]}

      cwes = issue.fetch('cwe_id', []).map { |cwe| "CWE-#{cwe}" }

      return parse_error(issue) if issue.key?('error')

      {
        id: issue['warning_code'].to_s,
        name: "#{issue['check_name']}/#{issue['warning_type']}",
        level: issue['confidence'].upcase,
        details: (issue['message']).to_s,
        messageStrings: { "title": { "text": (issue['check_name']).to_s },
                          "type": { "text": (issue['warning_type']).to_s },
                          "warning_code": { "text": (issue['warning_code']).to_s },
                          "cwe": { "text": cwes.to_s } },
        properties: { 'fingerprint': issue['fingerprint'].to_s,
                      'confidence': issue['confidence'].to_s,
                      'severity': "",
                      'render_path': issue['render_path'].to_s,
                      'user_input': issue['user_input'].to_s,
                      'location_type': issue.dig('location', 'type').to_s,
                      'location_class': issue.dig('location', 'class').to_s,
                      'location_method': issue.dig('location', 'method').to_s },
        start_line: issue['line'].to_i,
        start_column: 1,
        uri: issue['file'],
        help_url: issue['link'],
        code: issue['code']
      }
    end
  end
end
