module Sarif
  class CargoAuditSarif < BaseSarif
    include Salus::SalusBugsnag

    CARGO_AUDIT_URI = 'https://github.com/RustSec/cargo-audit/'.freeze

    def initialize(scan_report, repo_path = nil, scanner_config = {})
      super(scan_report, {}, repo_path)
      @uri = CARGO_AUDIT_URI
      @logs = parse_scan_report!
      @scanner_config = scanner_config
    end

    def parse_scan_report!
      logs = @scan_report.log('')
      return [] if logs.strip.empty?

      x = JSON.parse(logs)
      vulnerabilities = x['vulnerabilities']['list'] || []
      unmaintained = x['warnings']['unmaintained'] || []
      yanked = x['warnings']['yanked'] || []
      vulnerabilities.concat(unmaintained, yanked)
    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      []
    end

    def parse_yanked(issue)
      package = issue['package']
      return nil if issue.include?(package['name'] + '/ Yanked')

      @issues.add(package['name'] + '/ Yanked')
      {
        id: package['name'] + '/ Yanked',
        name: package['name'] + '/ Yanked',
        level: "low",
        details: "Package:#{package['name']}\nVersion:#{package['version']}\nSource:"\
        "#{package['source']}\nKind: yanked",
        uri: 'Cargo.lock',
        help_url: package['source']
      }
    end

    def parse_issue(issue)
      return parse_yanked(issue) if issue['kind'] == 'yanked'
      return nil if @issues.include?(issue.dig('advisory', 'id'))

      # rubocop:disable Layout/LineLength

      # Example issue
      # {"advisory"=>
      # {"id"=>"RUSTSEC-2019-0010",
      # "package"=>"libflate",
      # "title"=>"MultiDecoder::read() drops uninitialized memory of ...",
      # "description"=>
      #  "Affected versions of libflate have set a field of an internalnd revert ...",
      # "date"=>"2019-07-04",
      # "aliases"=>["CVE-2019-15552"],
      # "related"=>[],
      # "collection"=>"crates",
      # "categories"=>[],
      # "keywords"=>["drop", "use-after-free"],
      # "cvss"=>"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      # "informational"=>nil,
      # "references"=>[],
      # "source"=>nil,
      # "url"=>"https://github.com/sile/libflate/issues/35",
      # "withdrawn"=>nil},
      # "versions"=>{"patched"=>[">=0.1.25"], "unaffected"=>["<0.1.14"]},
      # "affected"=>{"arch"=>[], "os"=>[], "functions"=>{"libflate::gzip::MultiDecoder::read"=>["<0.1.25, >=0.1.14"]}},
      # "package"=>
      # {"name"=>"libflate",
      # "version"=>"0.1.19",
      # "source"=>"registry+https://github.com/rust-lang/crates.io-index",
      # "checksum"=>nil,
      # "dependencies"=>
      #  [{"name"=>"adler32", "version"=>"1.1.0", "source"=>"registry+https://github.com/rust-lang/crates.io-index"},
      #   {"name"=>"crc32fast", "version"=>"1.2.0", "source"=>"registry+https://github.com/rust-lang/crates.io-index"},
      #   {"name"=>"rle-decode-fast", "version"=>"1.0.1", "source"=>"registry+https://github.com/rust-lang/crates.io-index"},
      #   {"name"=>"take_mut", "version"=>"0.2.2", "source"=>"registry+https://github.com/rust-lang/crates.io-index"}],
      # "replace"=>nil}}

      # rubocop:enable Layout/LineLength

      # !!!! Note CVEs are not CWEs but we lack a mapping to CWE
      cves = issue.dig('advisory', 'aliases')
      cves = [] if cves.nil?

      @issues.add(issue.dig('advisory', 'id'))
      advisory = issue['advisory'] || {}
      parsed_issue = {
        id: advisory['id'],
        name: advisory['title'],
        level: "HIGH",
        details: (advisory['description']).to_s,
        messageStrings: { "package": { "text": (advisory['package']).to_s },
                         "title": { "text": (advisory['title']).to_s },
                         "severity": { "text": (advisory['cvss']).to_s },
                         "cwe": { "text": cves.to_s },
                         "patched_versions": { "text": issue.dig('versions', 'patched').to_s },
                         "unaffected_versions": { "text": issue.dig('versions',
                                                                    'unaffected').to_s } },
        properties: { 'severity': (advisory['cvss']).to_s },
        uri: 'Cargo.lock',
        help_url: issue['advisory']['url']
      }

      version = issue.dig('package', 'version')
      if !version.nil? && Gem::Version.correct?(version)
        parsed_issue[:properties][:detected_versions] = [version]
      end

      if issue['kind'] == 'unmaintained'
        parsed_issue[:level] = 'LOW'
        parsed_issue[:details] << "\nKind: unmaintained"
      end
      parsed_issue
    end
  end
end
