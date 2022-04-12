require 'json'

module Salus
  class GradleDependencyParser
    attr_reader :gradle_dependencies
    def initialize(path)
      msg = "Repository not found!"
      raise StandardError, msg unless path.present?

      @gradle_content = run_shell(["cd #{path} && gradle dependencies"], chdir: nil)
      @gradle_dependencies = []
    end

    def parse
      raise StandardError, @gradle_content.stderr if !@gradle_content.success?

      dependency_metadata_regex = /-\s(?<group_id>.+):(?<artifact_id>.+):(?<version>.+)/
      @gradle_content.stdout.scan(dependency_metadata_regex).each do |dependency_properties|
        dependency_hash = {
          "group_id" => dependency_properties[0],
          "artifact_id" => dependency_properties[1],
          "version" => dependency_properties[2]
        }
        @gradle_dependencies.append(dependency_hash)
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
