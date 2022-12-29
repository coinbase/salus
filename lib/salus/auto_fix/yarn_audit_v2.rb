require 'uri'
require 'salus/yarn_formatter'
require 'salus/auto_fix/base'

module Salus::Autofix
  class YarnAuditV2 < Base
    def initialize(path_to_repo)
      @path_to_repo = path_to_repo
    end

    def run_auto_fix
      shell_return = run_shell("npx yarn-audit-fix", chdir: @path_to_repo)
      return true if shell_return.stdout.include?("success Saved lockfile.")

      false
    end
  end
end
