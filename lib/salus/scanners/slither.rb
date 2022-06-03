require 'json'
require 'salus/scanners/base'

# Slither (https://github.com/crytic/slither) is a Python-based static
# analysis tool for Solidity smart contracts

module Salus::Scanners
  class Slither < Base
    include Salus::Formatting

    def should_run?
      # only support truffle/hardhat for now
      return false if !@repository.package_json_present? || !has_package_config

      @repository.sol_file_present? != false
    end

    def run
      # Most Solidity projects will be Hardhat (https://hardhat.org/) or Truffle (https://trufflesuite.com/),
      # which both use NPM to manage Solidity dependencies. We should NPM install in these cases
      # to ensure Slither has the needed dependencies for scanning

      shell_return = run_shell("npm install", chdir: @repository.path_to_repo)
      if !shell_return.success?
        err_msg = 'npm install failed! ' + shell_return.stderr
        report_error(err_msg)
        report_stderr(err_msg)
        return report_failure
      end

      shell_return = run_shell("npm config set user 0")
      if !shell_return.success?
        err_msg = 'npm config set user failed! ' + shell_return.stderr
        report_error(err_msg)
        report_stderr(err_msg)
        return report_failure
      end

      shell_return = run_shell(command, chdir: @repository.path_to_repo)
      return report_success if shell_return.success?

      report_failure

      begin
        stdout_json = JSON.parse(shell_return.stdout)
      rescue JSON::ParserError
        err_msg = "Could not parse slither json stdout: " + shell_return.stdout
        report_error(err_msg)
        report_stderr(err_msg)
        return
      end

      if !stdout_json['success'] || !stdout_json['error'].nil? || stdout_json['results'].nil?
        # An error during compilation occurred
        scanning_error = stdout_json['error']
        report_error(scanning_error)
        report_stderr(scanning_error)
      else
        results = []
        stdout_json['results']['detectors'].each do |r|
          result = {}
          %w[description first_markdown_element check impact confidence].each do |k|
            result[k] = r[k]
          end
          results.push(result)
        end
        report_stdout(JSON.pretty_generate(results))
        log(JSON.pretty_generate(results))
      end
    end

    def version
      run_shell('slither --version').stdout.rstrip
    end

    def self.supported_languages
      ['solidity']
    end

    protected

    def command
      #      "slither . --json - --exclude-low --exclude-informational --exclude-optimization"
      # "slither . --exclude-low --exclude-informational --exclude-optimization"
      "slither . --json - --exclude-informational --exclude-optimization"
      # "npm config set user 0; slither . --exclude-informational --exclude-optimization"
    end

    private

    def has_package_config
      truffle_script_present = @repository.truffle_js_present? ||
        @repository.truffle_ts_present? ||
        @repository.truffle_config_js ||
        @repository.truffle_config_ts
      hardhat_config_present = @repository.hardhat_config_js_present? ||
        @repository.hardhat_config_ts_present?
      truffle_script_present || hardhat_config_present
    end
  end
end
