require 'salus/scanners/base'

# Report python library usage

module Salus::Scanners
  class ReportPythonModules < Base
    def run
      begin
        parser = Salus::PythonDependencyParser.new(@repository.path_to_repo)
        parser.parse
      rescue StandardError => e
        report_stderr(e.message)
        report_error(e.message)
      end

      parser.requirements_txt_dependencies.each do |dependency|
        report_dependency(
          dependency["dependency_file"],
          type: dependency["type"],
          name: dependency["name"],
          version: dependency["version"]
        )
      end
    end

    def should_run?
      @repository.requirements_txt_present?
    end

    def self.supported_languages
      ['python']
    end
  end
end
