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
      run_shell("npm install", chdir: @repository.path_to_repo)

      shell_return = run_shell(command, chdir: @repository.path_to_repo)
      stdout_json = begin
        JSON.parse(shell_return.stdout)
                    rescue JSON::ParserError
                      json_parser_error_msg = "Could not parse slither stdout"
                      "{ \"success\": false, \"error\": \"#{json_parser_error_msg}\" }"
      end

      return report_success if shell_return.success?

      report_failure

      if !stdout_json['success'] || !stdout_json['error'].nil?
        # An error during compilation occurred
        scanning_error = stdout_json['error']
        report_error(scanning_error)
        report_stderr(scanning_error)
      else
        report_stdout(
          'To allowlist findings from a detector, add a '\
          '`//slither-disable-next-line DETECTOR_NAME` comment before the '\
          'offending line.\n\nFor example, `//slither-disable-next-line '\
          'timestamp` will disable detection of `block.timestamp` usage by disabling the '\
          '`timestamp` detector.'
        )
        report_stdout(shell_return.stdout)
        log(prettify_json_string(shell_return.stdout))
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
      "slither . --json - --exclude-low --exclude-informational --exclude-optimization"
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
