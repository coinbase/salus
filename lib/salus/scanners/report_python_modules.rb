require 'salus/scanners/base'

# Report python library usage

module Salus::Scanners
  class ReportPythonModules < Base
    class PyPiApiError < StandardError; end
    class ApiTooManyRequestsError < StandardError; end

    MAX_RETRIES_FOR_API = 2

    def self.scanner_type
      Salus::ScannerTypes::SBOM_REPORT
    end

    def run
      shell_return = run_shell(['bin/report_python_modules',
                                @repository.path_to_repo], chdir: nil)

      dependencies = JSON.parse(shell_return.stdout)

      dependencies.each do |name, version|
        puts find_licenses_for(name)
        report_dependency(
          'requirements.txt',
          type: 'pypi',
          name: name,
          version: version,
          licenses: find_licenses_for(name)
        )
      end
    end

    def should_run?
      @repository.requirements_txt_present?
    end

    def self.supported_languages
      ['python']
    end

    private

    def find_licenses_for(name)
      res = send_request_to(name)

      return [] if res.nil?
      return [] if res.is_a?(Net::HTTPNotFound)

      raise PyPiApiError, res.body unless res.is_a?(Net::HTTPSuccess)

      licenses = JSON.parse(res.body).dig("info", "license")
      [licenses]
    rescue RubyGemsApiError, StandardError => e
      msg = "Unable to gather license information " \
        "using pypi api " \
        "with error message #{e.class}: #{e.message}"
      bugsnag_notify(msg)

      []
    end

    def send_request_to(name)
      retries = 0

      begin
        uri = pypi_uri_for(name)
        res = Net::HTTP.get_response(uri)

        raise ApiTooManyRequestsError if res.is_a?(Net::HTTPTooManyRequests)

        res
      rescue ApiTooManyRequestsError
        if retries < MAX_RETRIES_FOR_API
          retries += 1
          max_sleep_seconds = Float(2**retries)
          sleep rand(0..max_sleep_seconds)
          retry
        else
          msg = "Too many requests for pypi api after " \
            "#{retries} retries"
          bugsnag_notify(msg)

          nil
        end
      end
    end

    def pypi_uri_for(name)
      URI("https://pypi.org/pypi/#{name}/json")
    end
  end
end
