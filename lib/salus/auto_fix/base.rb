require 'open3'
require 'salus/plugin_manager'
require 'salus/shell_result'

module Salus::Autofix
  class Base
    class AutofixError < StandardError; end

    def initialize; end

    def write_auto_fix_files(path_to_repo, file, content)
      Dir.chdir(path_to_repo) do
        File.open(file, 'w') { |f| f.write(content) }
        raise AutofixError, "cannot find #{file}" if !File.exist?(file)
      end
    end

    # Runs a command on the terminal.
    def run_shell(command, env: {}, stdin_data: '',
                  chdir: '')
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
