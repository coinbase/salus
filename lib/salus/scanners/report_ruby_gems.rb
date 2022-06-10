require 'salus/scanners/base'
require 'salus/dice_coefficient'
require 'uri'
require 'net/http'

# Report the use of any Ruby gems.
module Salus::Scanners
  class ReportRubyGems < Base
    def self.scanner_type
      Salus::ScannerTypes::SBOM_REPORT
    end

    class RubyGemsApiError < StandardError; end

    class ApiTooManyRequestsError < StandardError; end

    SPDX_SCHEMA_FILE = 'lib/cyclonedx/schema/spdx.schema.json'.freeze
    MAX_RETRIES_FOR_RUBY_GEMS_API = 2

    def run
      # A lockfile is the most definitive source of truth for what will run
      # in production. It also lists the dependencies of dependencies.
      # We preference parsing the Gemfile.lock over the Gemfile.
      if @repository.gemfile_lock_present?
        record_dependencies_from_gemfile_lock
      elsif @repository.gemfile_present?
        record_dependencies_from_gemfile
      else
        raise InvalidScannerInvocationError,
              'Cannot report on Ruby gems without a Gemfile or Gemfile.lock'
      end
    end

    def should_run?
      @repository.gemfile_present? || @repository.gemfile_lock_present?
    end

    def self.supported_languages
      ['ruby']
    end

    private

    def record_dependencies_from_gemfile_lock
      lockfile = Bundler::LockfileParser.new(@repository.gemfile_lock)

      # lockfile.bundler_version isn't a string, so stringify it first
      report_info(:ruby_version, lockfile.ruby_version)
      report_info(:bundler_version, lockfile.bundler_version.to_s)

      lockfile.specs.each do |gem|
        record_ruby_gem(
          name: gem.name,
          version: gem.version.to_s,
          source: gem.source.to_s,
          dependency_file: 'Gemfile.lock'
        )
      end
    end

    def record_dependencies_from_gemfile
      ruby_project = Bundler::Definition.build("#{@repository.path_to_repo}/Gemfile", nil, nil)

      # Record ruby version if present in Gemfile.
      if ruby_project.ruby_version
        ruby_version = ruby_project.ruby_version.versions.first
        report_info(:ruby_version, ruby_version)
      end

      # Record ruby gems.
      ruby_project.dependencies.each do |gem|
        record_ruby_gem(
          name: gem.name,

          # For a Gemfile, the best estimation of the version is the requirement.
          version: gem.requirement.to_s,

          # Gem uses the given source, otherwise Bundler has a default.
          source: gem.source.nil? ? Gem.sources.first.uri.to_s : gem.source.to_s,

          dependency_file: 'Gemfile'
        )
      end
    end

    def record_ruby_gem(name:, version:, source:, dependency_file:)
      report_dependency(
        dependency_file,
        type: 'gem',
        name: name,
        version: version,
        source: source,
        licenses: find_licenses_for(name, version)
      )
    end

    def find_licenses_for(gem_name, version)
      res = send_request_to(ruby_gems_uri_for(gem_name, version))

      return [] if res.nil?
      return [] if res.is_a?(Net::HTTPNotFound)

      raise RubyGemsApiError, res.body unless res.is_a?(Net::HTTPSuccess)

      licenses = JSON.parse(res.body)['licenses']

      return [] if licenses.nil? || !licenses.is_a?(Array)

      licenses.map { |license| spdx_license_for(license) }
    rescue RubyGemsApiError, StandardError => e
      msg = "Unable to gather license information " \
        "using rubygems api " \
        "with error message #{e.class}: #{e.message}"
      bugsnag_notify(msg)

      []
    end

    # Send request to rubygems-org-api-v2
    # with exponential backoff
    def send_request_to(ruby_gems_uri)
      retries = 0

      begin
        res = Net::HTTP.get_response(ruby_gems_uri)

        raise ApiTooManyRequestsError if res.is_a?(Net::HTTPTooManyRequests)

        res
      rescue ApiTooManyRequestsError
        if retries < MAX_RETRIES_FOR_RUBY_GEMS_API
          retries += 1
          max_sleep_seconds = Float(2**retries)
          sleep rand(0..max_sleep_seconds)
          retry
        else
          msg = "Too many requests for rubygems api after " \
            "#{retries} retries"
          bugsnag_notify(msg)

          nil
        end
      end
    end

    def ruby_gems_uri_for(gem_name, version)
      URI("https://rubygems.org/api/v2/rubygems/#{gem_name}/versions/#{version}.json")
    end

    # Compares reported license with spdx licenses and returns closest match
    def spdx_license_for(license)
      @spdx_license_cache ||= {}

      @spdx_license_cache[license] ||=
        begin
          licenses_with_cof = spdx_formatted_licenses.each_with_object({}) do |spdx_license, memo|
            memo[spdx_license] = Salus::DiceCoefficient.dice(license, spdx_license)
          end

          licenses_with_cof.max_by { |_, co_efficient| co_efficient }&.first
        end

      @spdx_license_cache[license]
    end

    def spdx_formatted_licenses
      @spdx_formatted_licenses ||= JSON.parse(File.read(SPDX_SCHEMA_FILE))["enum"]
      @spdx_formatted_licenses
    end
  end
end
