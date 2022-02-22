require 'salus/scanners/base'
require 'json'
require 'zip'
require 'uri'
require 'net/http'

module Salus::Scanners::OSV
  class Base < Salus::Scanners::Base
    class ApiTooManyRequestsError < StandardError; end

    MAX_RETRIES = 2

    def run
      raise NoMethodError
    end

    def should_run?
      raise NoMethodError
    end

    private

    def name
      self.class.name.sub('Salus::Scanners::OSV::', '')
    end

    def osv_vulnerabilities
      @osv_vulnerabilities ||= fetch_vulnerabilities
    end

    def osv_url
      # Bucket location contains individual entries in OSVF.
      url = if @repository.go_sum_present? || @repository.go_mod_present?
              "https://osv-vulnerabilities.storage.googleapis.com/"\
              "Go/all.zip"
            elsif @repository.requirements_txt_present?
              "https://osv-vulnerabilities.storage.googleapis.com/"\
              "PyPI/all.zip"
            elsif @repository.pom_xml_present?
              "https://osv-vulnerabilities.storage.googleapis.com/"\
              "Maven/all.zip"
            elsif @repository.gemfile_present? || @repository.gemfile_lock_present?
              "https://osv-vulnerabilities.storage.googleapis.com/"\
              "RubyGems/all.zip"
            elsif @repository.cargo_present? || @repository.cargo_lock_present?
              "https://osv-vulnerabilities.storage.googleapis.com/"\
              "crates.io/all.zip"
            elsif @repository.package_lock_json_present?
              "https://osv-vulnerabilities.storage.googleapis.com/"\
              "npm/all.zip"
            end
      URI(url)
    end

    def fetch_vulnerabilities
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

      all_vulnerabilities_found
    rescue StandardError => e
      report_error("Connection to OSV failed: #{e}")
    rescue ApiTooManyRequestsError
      if retries < MAX_RETRIES
        retries += 1
        max_sleep_seconds = Float(2**retries)
        sleep rand(0..max_sleep_seconds)
        retry
      else
        msg = "Too many requests to OSV url after " \
        "#{retries} retries"
        report_error("Connection to OSV failed: #{msg}")
      end
    end

    def flatten_by_affected(doc)
      flattened_results = []
      affected_list = doc.delete("affected")
      affected_list.each do |affected|
        flattened_doc = doc.merge(affected)
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
      response = Net::HTTP.get_response(osv_url)
      if response.is_a?(Net::HTTPSuccess)
        # Response is returned as a zip with a list of JSON files. This loop
        # combines JSON files into an array.
        Zip::InputStream.open(StringIO.new(response.body)) do |io|
          vulns.append(JSON.parse(io.read)) while io.get_next_entry
        end
      elsif response.is_a?(Net::HTTPTooManyRequests)
        raise(ApiTooManyRequestsError, response.body)
      else
        raise(StandardError, response.body)
      end
      msg = "Connection to OSV failed: No data returned from GCS bucket."
      raise(StandardError, msg) if vulns.empty?

      vulns
    end
  end
end
