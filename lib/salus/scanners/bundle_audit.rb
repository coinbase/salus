require 'bundler/audit/cli'
require 'salus/scanners/base'

# BundlerAudit scanner to check for CVEs in Ruby gems.
# https://github.com/rubysec/bundler-audit

module Salus::Scanners
  class BundleAudit < Base
    class UnvalidGemVulnError < StandardError; end

    def run
      # Ensure the DB is up to date
      unless Bundler::Audit::Database.update!(quiet: true)
        report_error("Error updating the bundler-audit DB!")
        return
      end

      ignore = @config.fetch('ignore', [])
      scanner = Bundler::Audit::Scanner.new(@repository.path_to_repo)

      vulns = []
      scanner.scan(ignore: ignore) { |result| vulns.push(serialize_vuln(result)) }

      report_info(:ignored_cves, ignore)
      report_info(:vulnerabilities, vulns)

      vulns.empty? ? report_success : report_failure
    end

    def should_run?
      @repository.gemfile_lock_present?
    end

    private

    def serialize_vuln(vuln)
      case vuln
      when Bundler::Audit::Scanner::InsecureSource
        {
          type: 'InsecureSource',
          source: vuln.source
        }
      when Bundler::Audit::Scanner::UnpatchedGem
        {
          type: 'UnpatchedGem',
          name: vuln.gem.name,
          version: vuln.gem.version.to_s,
          cve: vuln.advisory.id,
          url: vuln.advisory.url,
          advisory_title: vuln.advisory.title,
          description: vuln.advisory.description,
          cvss: vuln.advisory.cvss_v2,
          osvdb: vuln.advisory.osvdb,
          patched_versions: vuln.advisory.patched_versions.map(&:to_s),
          unaffected_versions: vuln.advisory.unaffected_versions.map(&:to_s)
        }
      else
        raise UnvalidGemVulnError, "BundleAudit Scanner received a #{result} from the " \
                                   "bundler/audit gem, which it doesn't know how to handle"
      end
    end
  end
end
