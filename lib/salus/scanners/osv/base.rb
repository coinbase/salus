require 'salus/scanners/base'
require 'json'
require 'zip'
require 'uri'
require 'net/http'

module Salus::Scanners::OSV
  class Base < Salus::Scanners::Base
    def run
      raise NoMethodError, 'implement in subclass'
    end

    def should_run?
      raise NoMethodError, 'implement in subclass'
    end

    def name
      self.class.name.sub('Salus::Scanners::OSV::', '')
    end

    private

    def osv_vulnerabilities
      @osv_vulnerabilities ||= fetch_vulnerabilities
    end

    def osv_url
      urls = []
      # Bucket contains individual entries for an ecosystem in OSVF.
      urls.append(osv_url_for("Go")) if @repository.go_sum_present? || @repository.go_mod_present?
      urls.append(osv_url_for("PyPI")) if @repository.requirements_txt_present?
      urls.append(osv_url_for("Maven")) if @repository.pom_xml_present?

      urls
    end

    def osv_url_for(package)
      # Approximate zip sizes
      # Go: all.zip (478 KB) -> 1.1 MB
      # PyPI: all.zip (3.4 MB) -> 10.9 MB
      # Maven: all.zip (1.6 MB) -> 5.1 MB
      url = "https://osv-vulnerabilities.storage.googleapis.com/"\
      + package + "/all.zip"
      URI(url)
    end

    def fetch_vulnerabilities
      results = []
      all_vulnerabilities_found = []

      # Flatten vulnerabilities by package name.
      all_vulnerabilities = send_request

      all_vulnerabilities.each do |vulnerability|
        all_vulnerabilities_found.append(flatten_by_affected(vulnerability))
      end
      all_vulnerabilities_found.flatten!

      # Handle removing exception ids from vulnerabilities found.
      exception_ids = fetch_exception_ids
      if exception_ids.any? && all_vulnerabilities_found.any?
        all_vulnerabilities_found.delete_if do |v|
          identifiers_found = v.fetch("aliases", []) + [v.fetch("id")]
          intersection = identifiers_found & exception_ids
          true if intersection.length.positive?
        end
      end

      # Group vulnerabilities by aliases / id
      # Picks 1 item from each grouped item
      # { "ID-1": [
      #      {"name": "sample-dep-1"},  {"name": "sample-dep-1"}
      #    ]
      # }
      grouped = all_vulnerabilities_found.group_by { |d| d.fetch("aliases", [d.fetch("id")]) }
      grouped.each do |_key, values|
        advisory = {}
        # Prefer picking github advisory over other sources.
        # Github Advisory ID is of the format 'GHSA-xxx-xxx'
        values.each do |v|
          id_prefix = v.fetch("id", "").split("-")
          advisory = v if id_prefix[0] == "GHSA"
          break
        end
        # If Github Advisory not found pick first value.
        advisory = values[0] if advisory.empty?
        results.append(advisory)
      end
      results
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

    def format_vulns(vulns)
      str = ""
      vulns.each do |vul|
        vul.each do |k, v|
          str += "#{k}: #{v}\n"
        end
        str += "\n"
      end
      str
    end

    def send_request
      vulns = []
      urls = osv_url
      raise(StandardError, msg) if urls.empty?

      urls.each do |url|
        response = Net::HTTP.get_response(url)
        if response.is_a?(Net::HTTPSuccess)
          # Response is returned as a zip with a list of JSON files. This loop
          # combines JSON files into an array.
          Zip::InputStream.open(StringIO.new(response.body)) do |io|
            vulns.append(JSON.parse(io.read)) while io.get_next_entry
          end
        else
          raise(StandardError, response.body)
        end
      end
      msg = "Connection to OSV failed: No data found from GCS bucket."
      raise(StandardError, msg) if vulns.empty?

      vulns
    end
  end
end
