require 'salus/scanners/base'

# Report Swift usage

module Salus::Scanners
  class ReportSwiftDeps < Base
    class ReportSwiftDepsError < StandardError; end

    def self.scanner_type
      Salus::ScannerTypes::SBOM_REPORT
    end

    def run
      shell_return =
        run_shell(
          "bin/parse_package_resolved #{@repository.package_resolved_path}",
          chdir: nil
        )

      if !shell_return.success?
        report_error(shell_return.stderr)
        return
      end

      begin
        dependencies = JSON.parse(shell_return.stdout)

        raise ReportSwiftDepsError if dependencies.nil?

        dependencies.each do |dependency|
          report_dependency(
            'Package.resolved',
            type: 'swift',
            name: dependency['package'],
            version: dependency['version'],
            source: dependency['source']
          )
        end
      rescue ReportSwiftDepsError, JSON::ParserError
        err_msg = "Could not parse JSON returned by bin/parse_package_resolved's stdout!"
        report_stderr(err_msg)
        report_error(err_msg)
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
