require 'faraday'

module Salus
  class ReportRequest
    CONTENT_TYPE_FOR_FORMAT = {
      'json' => 'application/json',
      'yaml' => 'text/x-yaml',
      'txt'  => 'text/plain',
      'sarif' => 'application/json',
      'sarif_diff' => 'application/json',
      'sarif_diff_full' => 'application/json',
      'cyclonedx-json' => 'application/json'
    }.freeze

    FORMAT_SARIF_DIFF = "sarif_diff".freeze
    FORMAT_SARIF = "sarif".freeze
    FORMAT_SARIF_DIFF_FULL = "sarif_diff_full".freeze
    SCANNER_TYPE_SARIF_DIFF = "salus_sarif_diff".freeze
    SCANNER_TYPE_SARIF = "salus_sarif".freeze
    SCANNER_TYPE_SALUS = "salus".freeze

    class << self
      def send_report(config, data, remote_uri)
        format = config['format']

        conn = Faraday.new(
          url: remote_uri,
          headers: report_headers_h(config['headers'] || {}, format)
        )
        verb = config&.key?('put') ? :put : :post
        response = conn.send(verb) { |req| req.body = data }

        unless response.success?
          raise Salus::Report::ExportReportError,
                "Salus report to #{remote_uri} had response status #{response.status}."
        end
      end

      def report_headers_h(headers, format)
        header_hash = {}
        header_hash['Content-Type'] = CONTENT_TYPE_FOR_FORMAT[format]
        header_hash['X-Scanner'] = x_scanner_type(format)
        header_hash.merge!(headers)
      end

      def x_scanner_type(format)
        return SCANNER_TYPE_SARIF_DIFF if format == FORMAT_SARIF_DIFF
        return SCANNER_TYPE_SARIF if [FORMAT_SARIF, FORMAT_SARIF_DIFF_FULL].include?(format)

        SCANNER_TYPE_SALUS
      end
    end
  end
end
