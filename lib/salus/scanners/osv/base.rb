require 'salus/scanners/base'
require 'json'
require 'zip'
require 'uri'
require 'net/http'

module Salus::Scanners::OSV
  class Base < Salus::Scanners::Base
    # Repo - https://github.com/google/osv
    # Data - https://osv.dev/list
    DATABASE_STRING_MAPPING = {
      "GHSA" => "Github Advisory Database",
      "PYSEC" => "Python Packaging Advisory Database",
      "GO" => "Go Vulnerability Database",
      "RUSTSEC" => "RustSec Advisory Database",
      "default" => "Open Source Vulnerabilitiy"
    }.freeze
    GITHUB_DATABASE_STRING = "Github Advisory Database".freeze

    def self.scanner_type
      Salus::ScannerTypes::DEPENDENCY
    end

    def run
      raise NoMethodError, 'implement in subclass'
    end

    def should_run?
      raise NoMethodError, 'implement in subclass'
    end

    def self.supported_languages
      []
    end

    def name
      self.class.name.sub('Salus::Scanners::OSV::', '')
    end

    private

    # Group and select Github Advisory over other sources when available.
    def group_vulnerable_dependencies(dependencies)
      results = []
      grouped = dependencies.group_by { |d| d[:ID] }
      grouped.each do |_key, values|
        vuln = {}
        values.each do |v|
          vuln = v if v[:Database] == GITHUB_DATABASE_STRING
        end
        results.append(vuln.empty? ? values[0] : vuln)
      end
      results
    end

    def fetch_vulnerabilities(url)
      raise(StandardError, "OSV Scanner: Empty url supplied from base class") if url.empty?

      all_vulnerabilities = send_request(url)
      all_vulnerabilities_found = []
      all_vulnerabilities.each do |vulnerability|
        # Flatten vulnerabilities by package name.
        all_vulnerabilities_found.append(flatten_by_affected(vulnerability))
      end
      all_vulnerabilities_found.flatten!

      # Handle removing exception ids from vulnerabilities found.
      exception_ids = fetch_exception_ids
      if exception_ids.any? && all_vulnerabilities_found.any?
        all_vulnerabilities_found.delete_if do |v|
          identifiers_found = v.fetch("aliases", []) + [v.fetch("id")]
          intersection = identifiers_found & exception_ids
          intersection.length.positive?
        end
      end

      # Add database field for identifying sources.
      all_vulnerabilities_found.each do |vulnerability|
        prefix = vulnerability.fetch("id", "").split("-")[0]
        vulnerability["database"] = DATABASE_STRING_MAPPING.fetch(
          prefix,
          DATABASE_STRING_MAPPING["default"]
        )
      end

      all_vulnerabilities_found
    rescue StandardError => e
      bugsnag_notify(e.message)
      report_error("Connection to OSV failed: #{e}")
    end

    # Converts list of affected into multiple documents.
    # BEFORE = [
    #   {"id": "ID-1",
    #     "affected": [
    #       {"package": {"name": "sample-dep-1"},"ecosystem_specific": {}},
    #       {"package": {"name": "sample-dep-2"}, "ecosystem_specific": {}}
    #     ]
    #   }
    # ]
    # AFTER = [
    #  {"id": "ID-1", "package": {"name": "sample-dep-1"}, "ecosystem_specific": {}},
    #  {"id": "ID-1", "package": {"name": "sample-dep-2"}, "ecosystem_specific": {}}
    #  ]
    def flatten_by_affected(doc)
      flattened_results = []
      affected_list = doc.delete("affected")
      affected_list.each do |affected|
        flattened_doc = affected.merge(doc)
        flattened_results.append(flattened_doc)
      end
      flattened_results
    end

    def send_request(url)
      vulns = []
      response = Net::HTTP.get_response(URI(url))
      if response.is_a?(Net::HTTPSuccess)
        # Response is returned as a zip with a list of JSON files. This loop
        # combines JSON files into an array.
        # zip contains individual entries for an ecosystem in OSV format.
        # Approximate zip sizes
        # Go: all.zip (478 KB) -> 1.1 MB
        # PyPI: all.zip (3.4 MB) -> 10.9 MB
        # Maven: all.zip (1.6 MB) -> 5.1 MB
        Zip::InputStream.open(StringIO.new(response.body)) do |io|
          vulns.append(JSON.parse(io.read)) while io.get_next_entry
        end
      else
        raise(StandardError, response.body)
      end
      msg = "Connection to OSV failed: No data found from GCS bucket."
      raise(StandardError, msg) if vulns.empty?

      vulns
    end
  end
end
