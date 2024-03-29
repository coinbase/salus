module Sarif
  class NPMAuditSarif < BaseSarif
    NPM_URI = 'https://docs.npmjs.com/cli/v7/commands/npm-audit'.freeze

    def initialize(scan_report, repo_path = nil, scanner_config = {})
      super(scan_report, {}, repo_path)
      @uri = NPM_URI
      @logs = parse_scan_report!
      @exceptions = Set.new(@scan_report.to_h.dig(:info, :exceptions))
      @results = []
      @scanner_config = scanner_config
    end

    def parse_scan_report!
      log = @scan_report.to_h.dig(:info, :stdout, :advisories)
      return [] if log.nil?

      log.values
    end

    def parse_issue(issue)
      id = issue[:id].to_s
      return nil if @issues.include?(id) || @exceptions.include?(id)

      @results.push(id) if !@exceptions.include?(id)
      @issues.add(id)

      # rubocop:disable Layout/LineLength

      # Example issue
      # {:findings=>[{:version=>"1.2.0", :paths=>["merge"]}],
      # :metadata=>nil,
      # :vulnerable_versions=>"<2.1.1",
      # :module_name=>"merge",
      # :severity=>"high",
      # :github_advisory_id=>"GHSA-7wpw-2hjm-89gp",
      # :cves=>["CVE-2020-28499"],
      # :access=>"public",
      # :patched_versions=>">=2.1.1",
      # :updated=>"2021-03-18T22:54:26.000Z",
      # :recommendation=>"Upgrade to version 2.1.1 or later",
      # :cwe=>"CWE-915",
      # :found_by=>nil,
      # :deleted=>nil,
      # :id=>1005415,
      # :references=>
      #    "- https://nvd.nist.gov/vuln/detail/CVE-2020-28499\n- https://github.com/yeikos/js.merge/commit/7b0ddc2701d813f2ba289b32d6a4b9d4cc235fb4\n- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1071049\n- https://snyk.io/vuln/SNYK-JS-MERGE-1042987\n- https://vuldb.com/?id.170146\n- https://github.com/yeikos/js.merge/blob/56ca75b2dd0f2820f1e08a49f62f04bbfb8c5f8f/src/index.ts#L64\n- https://github.com/yeikos/js.merge/blob/master/src/index.ts%23L64\n- https://github.com/advisories/GHSA-7wpw-2hjm-89gp",
      # :created=>"2021-11-18T16:00:48.538Z",
      # :reported_by=>nil,
      # :title=>"Prototype Pollution in merge",
      # :npm_advisory_id=>nil,
      # :overview=>"All versions of package merge <2.1.1 are vulnerable to Prototype Pollution via _recursiveMerge .",
      # :url=>"https://github.com/advisories/GHSA-7wpw-2hjm-89gp",
      # :line_number=>23}

      # rubocop:enable Layout/LineLength

      parsed_issue = {
        id: id,
        name: issue[:title],
        level: issue[:severity].upcase,
        details: (issue[:overview]).to_s,
        messageStrings: { "package": { "text": (issue[:module_name]).to_s },
                         "severity": { "text": (issue[:severity]).to_s },
                         "patched_versions": { "text": (issue[:patched_versions]).to_s },
                         "cwe": { "text": (issue[:cwe]).to_s },
                         "recommendation": { "text": (issue[:recommendation]).to_s },
                         "vulnerable_versions": { "text": (issue[:vulnerable_versions]).to_s } },
        properties: { 'severity': (issue[:severity]).to_s },
        uri: "package-lock.json",
        help_url: issue[:url],
        suppressed: @exceptions.include?(id)
      }

      if issue[:findings]&.all? { |v| Gem::Version.correct?(v[:version]) }
        versions = issue[:findings].map { |v| Gem::Version.new(v[:version]).to_s }
        parsed_issue[:properties][:detected_versions] = versions
      end

      if issue[:line_number]
        parsed_issue[:start_line] = issue[:line_number]
        parsed_issue[:start_column] = 1
        parsed_issue[:code] = issue[:module_name].to_s
      end

      parsed_issue
    end

    def sarif_level(severity)
      case severity
      when "LOW"
        SARIF_WARNINGS[:note]
      when "MODERATE"
        SARIF_WARNINGS[:warning]
      when "HIGH"
        SARIF_WARNINGS[:error]
      when "CRITICAL"
        SARIF_WARNINGS[:error]
      else
        SARIF_WARNINGS[:note]
      end
    end

    def build_invocations(scan_report, supported)
      invocation = super(scan_report, supported)
      invocation[:executionSuccessful] = @results.empty?
      invocation
    end

    def self.snippet_possibly_in_git_diff?(snippet, lines_added)
      snippet = "\"" + snippet + "\":"
      lines_added.keys.any? { |k| k.include? snippet }
    end
  end
end
