require 'faraday'

module Salus
  class ReportRequest
    CONTENT_TYPE_FOR_FORMAT = {
      'json' => 'application/json',
      'yaml' => 'text/x-yaml',
      'txt'  => 'text/plain',
      'sarif' => 'application/json',
      'sarif_diff' => 'application/json',
      'cyclonedx-json' => 'application/json'
    }.freeze

    class << self
      def send_report(config, data, remote_uri)
        format = config['format']

        conn = Faraday.new(
          url: remote_uri,
          headers: report_headers_h(config['headers'] || {}, format)
        )

        response = if config&.key?('put')
                     conn.put do |req|
                       req.body = data
                     end
                   else
                     conn.post do |req|
                       req.body = data
                     end
                   end

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
        if format == 'sarif_diff'
          "salus_sarif_diff"
        else
          "salus"
        end
      end
    end
  end
end
