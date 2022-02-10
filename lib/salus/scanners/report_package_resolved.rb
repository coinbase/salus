require 'salus/scanners/base'

# Report Swift usage

module Salus::Scanners
  class ReportPackageResolved < Base
    class ReportPackageResolvedError < StandardError; end

    def run
      shell_return =
        run_shell(
          "bin/parse_package_resolved #{@repository.path_to_repo}/Package.resolved",
          chdir: nil
        )

      if !shell_return.success?
        report_error(shell_return.stderr)
        return
      end

      begin
        dependencies = JSON.parse(shell_return.stdout)

        raise ReportPackageResolvedError if dependencies.nil?

        dependencies.each do |dependency|
          report_dependency(
            'Package.resolved',
            type: 'swift',
            name: dependency['package'],
            version: dependency['version']
          )
        end
      rescue ReportPackageResolvedError, JSON::ParserError
        err_msg = "Could not parse JSON returned by bin/parse_package_resolved's stdout!"
        report_stderr(err_msg)
        report_error(err_msg)
        nil
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
