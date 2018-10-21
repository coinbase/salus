require 'salus/scanners/base'

# Report python library usage

module Salus::Scanners
  class ReportPythonModules < Base
    DEP_PARSER = File.read(File.join(__dir__, 'report_python_modules.py'))

    def run
      Dir.chdir(@repository.path_to_repo) do
        shell_return = run_shell('python', stdin_data: DEP_PARSER)

        if shell_return.success?
          dependencies = JSON.parse(shell_return.stdout)
          dependencies.each do |name, version|
            record_dependency_info(
              {
                type: 'python_requirement',
                name: name,
                version: version
              },
              'requirements.txt'
            )
          end
        else
          report_error('message' => shell_return.stderr)
        end
      end
    end

    def should_run?
      @repository.requirements_txt_present?
    end
  end
end
