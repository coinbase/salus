require 'json'
require 'salus/scanners/base'

# Slither (https://github.com/crytic/slither) is a Python-based static 
# analysis tool for Solidity smart contracts

module Salus::Scanners
  class Slither < Base
    include Salus::Formatting

    def should_run?
      !!@repository.sol_file_present?
    end

    def run
      # Most Solidity projects will be Hardhat (https://hardhat.org/) or Truffle (https://trufflesuite.com/), 
      # which both use NPM to manage Solidity dependencies. We should NPM install in these cases to ensure 
      # Slither has the needed dependencies for scanning
      if @repository.package_json_present?
        run_shell("npm install", chdir: @repository.path_to_repo)
      end
      shell_return = run_shell(command, chdir: @repository.path_to_repo)
      stdout_json = JSON.parse(shell_return.stdout)

      return report_success if shell_return.success?

      report_failure

      if !stdout_json['success'] || !stdout_json['error'].nil?
        # puts prettify_json_string(shell_return.stdout)
        # An error during compilation occurred
        scanning_error = stdout_json['error']
        report_error(scanning_error)
        report_stderr(scanning_error)
      else
        # shell_return.stdout will be JSON of the discovered vulnerabilities
        report_stdout(shell_return.stdout)
        log(prettify_json_string(shell_return.stdout))
      end
    end

    def version
      shell_return = run_shell('slither --version')
      shell_return.stdout.rstrip()
    end

    def self.supported_languages
      ['solidity']
    end

    protected

    def command
      "slither . --json - --exclude-low --exclude-informational --exclude-optimization"
    end
  end
end
