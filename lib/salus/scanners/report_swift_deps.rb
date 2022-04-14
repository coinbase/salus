require 'salus/scanners/base'

# Report Swift usage

module Salus::Scanners
  class ReportSwiftDeps < Base
    class ReportSwiftDepsError < StandardError; end

    def run
      begin
        parser = Salus::SwiftDependencyParser.new(@repository.package_resolved_path)
        parser.parse
        if parser.swift_dependencies.empty?
          err_msg = "Could not parse dependencies from Package.resolved file"
          raise StandardError, err_msg
        end
      rescue StandardError => e
        report_stderr(e.message)
        report_error(e.message)
        return
      end
      parser.swift_dependencies.each do |dependency|
        report_dependency(
          'Package.resolved',
          type: 'swift',
          name: dependency['package'],
          version: dependency['version'],
          source: dependency['source']
        )
      end
    end

    def should_run?
      @repository.package_resolved_present?
    end

    def self.supported_languages
      %w[swift]
    end
  end
end
