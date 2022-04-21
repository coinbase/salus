require 'json'
require 'set'
require 'sarif/shared_objects'

module Sarif
  class BaseSarif
    include Sarif::SharedObjects

    DEFAULT_URI = "https://github.com/coinbase/salus".freeze

    SARIF_WARNINGS = {
      error: "error",
      warning: "warning",
      note: "note"
    }.freeze

    attr_accessor :config, :required # sarif_options

    def initialize(scan_report, config = {}, repo_path = nil)
      @scan_report = scan_report
      @mapped_rules = {} # map each rule to an index
      @rule_index = 0
      @logs = []
      @uri = DEFAULT_URI
      @issues = Set.new
      @config = config
      @repo_path = repo_path || Dir.getwd # Fallback, we should make repo_path required
    end

    def base_path
      @base_path ||= @repo_path.nil? ? nil : File.expand_path(@repo_path)
    end

    # Retrieve tool section for sarif report
    def build_tool(rules: [])
      {
        "driver": {
          "name" => @scan_report.scanner_name,
          "version" => @scan_report.version,
          "informationUri" => @uri,
          "rules" => rules,
          "properties" => {
            "salusEnforced": @required || false
          }
        }
      }
    end

    ##
    # Provide the originalUriBaseIds content hash.
    # ProjectRoot will be the absolute path to the scanned project
    # SrcRoot will be relative to the project root.
    # @returns [Hash]
    #
    def uri_info
      project_root = Pathname.new(base_path.to_s)
      srcroot = Pathname.new(File.expand_path(@scan_report.repository&.path_to_repo.to_s))
      src_uri = srcroot.relative_path_from(project_root).to_s

      # The originalUriBaseIds info
      {
        "PROJECTROOT": {
          "uri": "file://#{base_path}"
        },
        "SRCROOT": {
          "uri": src_uri,
          "uriBaseId": "PROJECTROOT"
        }
      }
    end

    # Retrieves result section for sarif report
    def build_result(parsed_issue)
      result = {
        "ruleId": parsed_issue[:id],
        "ruleIndex": @mapped_rules[parsed_issue[:id]],
        "level": sarif_level(parsed_issue[:level]),
        "message": {
          "text": parsed_issue[:details]
        },
        "locations": [
          {
            "physicalLocation": {
              "artifactLocation": {
                "uri": parsed_issue[:uri],
                "uriBaseId": "%SRCROOT%"
              }
            }
          }
        ]
      }
      location = result[:locations][0][:physicalLocation]
      if !parsed_issue[:start_line].nil?
        location[:region] = {
          "startLine": parsed_issue[:start_line].to_i,
          "startColumn": parsed_issue[:start_column].to_i
        }
      end

      location[:region][:snippet] = { "text": parsed_issue[:code] } if !parsed_issue[:code].nil?
      result[:properties] = parsed_issue[:properties] unless parsed_issue[:properties].nil?
      result
    end

    def build_rule(parsed_issue)
      # only include one entry per rule id
      if !@mapped_rules.include?(parsed_issue[:id])
        rule = {
          "id": parsed_issue[:id],
          "name": parsed_issue[:name],
          "fullDescription": {
            "text": parsed_issue[:details]
          },
          "messageStrings": parsed_issue[:messageStrings] || {},
          "helpUri": parsed_issue[:help_url] || '',
          "help": {
            "text": "More info: #{parsed_issue[:help_url]}",
            "markdown": "[More info](#{parsed_issue[:help_url]})."
          }
        }
        @mapped_rules[parsed_issue[:id]] = @rule_index
        @rule_index += 1
        rule[:fullDescription][:text] = "errors reported by scanner" if rule[:id] == SCANNER_ERROR
        rule
      end
    end

    # Returns the 'runs' object for a supported/unsupported scanner's report
    def build_runs_object(supported)
      results = []
      rules = []
      @logs.each do |issue|
        parsed_issue = parse_issue(issue)

        next if !parsed_issue

        next if parsed_issue[:suppressed] && @config.fetch('include_suppressed', true) == false

        not_required = (@required.nil? || @required == false)

        next if not_required && @config.fetch('include_non_enforced', true) == false

        rule = build_rule(parsed_issue)
        rules << rule if rule
        result = build_result(parsed_issue)

        # Add suppresion object for suppressed results
        if parsed_issue[:suppressed]
          result['suppressions'] = [{
            'kind': 'external'
          }]
        end
        results << result
      end

      # unique-ify the results
      results = results.each_with_object([]) { |h, result| result << h unless result.include?(h); }

      # Salus::ScanReport
      invocation = build_invocations(@scan_report, supported)
      {
        "tool" => build_tool(rules: rules),
        "conversion" => build_conversion,
        "results" => results,
        "invocations" => [invocation],
        "originalUriBaseIds" => uri_info
      }
    end

    # Returns the conversion object for the SARIF report
    def build_conversion
      {
        "tool": {
          "driver": {
            "name": "Salus",
            "informationUri": DEFAULT_URI
          }
        }
      }
    end

    # Returns a sarif wraning level for a given severity
    def sarif_level(severity)
      case severity
      when "LOW"
        SARIF_WARNINGS[:warning]
      when "MEDIUM"
        SARIF_WARNINGS[:error]
      when "HIGH"
        SARIF_WARNINGS[:error]
      else
        SARIF_WARNINGS[:note]
      end
    end

    def self.salus_passed?(sarif)
      sarif['runs'].each do |run|
        execution_succ = run['invocations'].all? { |inv| inv['executionSuccessful'] }
        scanner_enforced = run['tool']['driver']['properties']['salusEnforced']
        return false if scanner_enforced && !execution_succ
      end
      true
    end

    def self.new_lines_in_git_diff(git_diff)
      lines_added = {}
      git_diff.split("\n").each_with_index do |line, line_num|
        if line.start_with?('+') && !line.start_with?('++')
          line = line.split('+', 2)[1]
          lines_added[line] = [] if !lines_added[line]
          lines_added[line].push line_num
        end
      end
      lines_added
    end

    def self.report_diff(sarif_new, sarif_old, git_diff = '')
      old_scanner_info = {}
      delete_results = Set.new
      lines_added = new_lines_in_git_diff(git_diff)

      sarif_old["runs"].each do |run|
        if run["results"].size.positive?
          scanner = run["tool"]["driver"]["name"]
          run["results"].each { |result| result.delete("ruleIndex") }
          old_scanner_info[scanner] = Set.new run["results"]
        end
      end

      sarif_new["runs"].each do |run| # loop over results for each scanner
        scanner = run["tool"]["driver"]["name"]
        rule_ids = Set.new # rule ids of final results
        scanner_updated = false
        rule_index = 0

        run["results"].each do |result|
          result.delete('ruleIndex')
          if old_scanner_info[scanner]&.include?(result)
            delete_results.add result
            scanner_updated = true
          else
            if git_diff != ''
              locations = result['locations']
              if has_sarif_adapter?(scanner) && locations && !locations.empty? &&
                  locations.all? do |loc|
                    # rubocop outputs false positive here
                    # rubocop:disable Lint/AssignmentInCondition
                    snippet = loc&.dig('physicalLocation', 'region', 'snippet', 'text')
                    # rubocop:enable Lint/AssignmentInCondition
                    !snippet.to_s.empty? &&
                        !snippet_possibly_in_diff?(snippet, scanner, lines_added)
                  end
                delete_results.add result
                scanner_updated = true
                next
              end
            end

            result["ruleIndex"] = rule_index
            rule_ids.add result['ruleId']
            rule_index += 1
          end
        end

        run["results"].reject! { |result| delete_results.include?(result) }

        if scanner_updated # delete relevant rule ids from rules section
          run["tool"]["driver"]["rules"].select! { |rule| rule_ids.include? rule["id"] }
          if run["tool"]["driver"]["rules"].empty?
            run["invocations"][0]["executionSuccessful"] = true
          end
        end
      end

      sarif_new["runs"].each do |run|
        id_to_index = {}
        ids = run["results"].map { |r| r['ruleId'] }.uniq
        ids.each_with_index { |id, i| id_to_index[id] = i }

        run["results"].each do |result|
          result['ruleIndex'] = id_to_index[result['ruleId']]
        end
      end

      sarif_new
    end

    def self.has_sarif_adapter?(scanner)
      adapter = "Sarif::#{scanner}Sarif"
      begin
        adapter_cls = Object.const_get(adapter)
      rescue NameError
        return false
      end
      adapter_cls.respond_to?(:snippet_possibly_in_git_diff?)
    end

    def self.snippet_possibly_in_diff?(snippet, scanner, lines_added)
      adapter = "Sarif::#{scanner}Sarif"
      adapter_cls = Object.const_get(adapter)
      adapter_cls.snippet_possibly_in_git_diff?(snippet, lines_added)
    end
  end
end
