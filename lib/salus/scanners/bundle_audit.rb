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
        report_error('message' => "Error updating the bundler-audit DB!")
        return
      end

      begin
        # Create our scanner pointing to the repo directory
        scanner = Bundler::Audit::Scanner.new(@repository.path_to_repo)
      rescue Errno::ENOENT
        report_error('message' => "Errno::ENOENT - Invalid directory (directory doesn't exist)")
        return
      end

      # Report any ignored CVEs (called multiple times to flatten the results)
      @config['ignore']&.each do |cve|
        report_info('ignored_cves', cve)
      end

      vulns = []
      failed = false

      # Scan that mamma jamma, ignoring specified directories
      scanner.scan(ignore: @config['ignore']) do |result|
        vulns.push(serialize_vuln(result))
        failed = true
      end

      if failed
        report_stdout(JSON.pretty_generate(vulns))
        report_failure
      else
        report_success
      end
    end

    def should_run?
      @repository.gemfile_lock_present?
    end

    private

    def serialize_vuln(vuln)
      case vuln
      when Bundler::Audit::Scanner::InsecureSource
        serialized_vuln = {
          type: :InsecureSource,
          source: vuln.source
        }
        report_info("insecure_storage", serialized_vuln)
        serialized_vuln
      when Bundler::Audit::Scanner::UnpatchedGem
        serialized_vuln = {
          type: :UnpatchedGem,
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
        report_info("unpatched_gem", serialized_vuln)
        serialized_vuln
      else
        raise UnvalidGemVulnError, "BundleAudit Scanner received a #{result} from the " \
                                   "bundler/audit gem, which it doesn't know how to handle"
      end
    end
  end
end
