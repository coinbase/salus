require 'salus/scanners/base'

# Report python library usage

module Salus::Scanners
  class ReportPythonModules < Base
    def run
      shell_return = run_shell(['bin/report_python_modules', @repository.path_to_repo])

      if !shell_return.success?
        report_error(shell_return.stderr)
        return
      end

      dependencies = JSON.parse(shell_return.stdout)

      dependencies.each do |name, version|
        report_dependency(
          'requirements.txt',
          type: 'python_requirement',
          name: name,
          version: version
        )
      end
    end

    def should_run?
      @repository.requirements_txt_present?
    end
  end
end
