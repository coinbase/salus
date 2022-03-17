require 'json'

module Salus
  class PythonDependencyParser
    attr_reader :requirements_txt_dependencies
    def initialize(path)
      msg = "Repository not found!"
      raise StandardError, msg unless path.present?

      @requirements_txt_content = run_shell(['bin/report_python_modules',
                                             path], chdir: nil)
      @requirements_txt_dependencies = []
    end

    def parse
      raise StandardError, @requirements_txt_content.stderr if !@requirements_txt_content.success?

      dependencies = JSON.parse(@requirements_txt_content.stdout)
      dependencies.each do |name, version|
        @requirements_txt_dependencies.append(
          {
            "type" => 'pypi',
            "name" => name,
            "version" => version,
            "dependency_file" => 'requirements.txt'
          }
        )
      end
    end

    private

    # Runs a command on the terminal.
    def run_shell(command, env: {}, stdin_data: '',
                  chdir: File.expand_path(@repository&.path_to_repo))
      # If we're passed a string, convert it to an array before passing to capture3
      command = command.split unless command.is_a?(Array)
      Salus::PluginManager.send_event(:run_shell, command, chdir: chdir)
      #  chdir: '/some/directory'
      opts = { stdin_data: stdin_data }
      opts[:chdir] = chdir unless chdir.nil? || chdir == "."
      Salus::ShellResult.new(*Open3.capture3(env, *command, opts))
    end
  end
end
