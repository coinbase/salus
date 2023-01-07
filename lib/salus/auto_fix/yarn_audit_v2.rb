require 'uri'
require 'salus/yarn_formatter'
require 'salus/auto_fix/base'

module Salus::Autofix
  class YarnAuditV2 < Base
    BASE_COMMAND = "npx yarn-audit-fix".freeze
    REGISTRY_STRING = " --registry=".freeze

    def initialize(path_to_repo, config, yarn_path)
      @path_to_repo = path_to_repo
      @config = config
      @yarn_path = yarn_path
    end

    def run_auto_fix
      cmd = BASE_COMMAND
      # run auto fix command
      if @config.fetch("run", false)
        cmd += REGISTRY_STRING + @config.fetch("registry", "") if @config.fetch("registry", false)
        shell_return = run_shell(cmd, chdir: @path_to_repo)
        write_auto_fix_files(@path_to_repo, 'yarn-autofix.lock', File.read(@yarn_path))

        return true if shell_return.stdout.include?("success Saved lockfile.")
      end

      false
    end
  end
end
