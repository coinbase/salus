require 'json'
require 'salus/scanners/base'

# Slither (https://github.com/crytic/slither) is a Python-based static
# analysis tool for Solidity smart contracts

module Salus::Scanners
  class Slither < Base
    include Salus::Formatting

    REF_URL_PREFIX = 'https://github.com/crytic/slither/wiki/Detector-Documentation#'.freeze
    # TODO: in a separate PR, make --exclude-informational --exclude-optimization configurable
    # --exclude-informational - exclude informational impact analyses
    #     Ex. Variable names are too similar
    # --exclude-optimization - exclude optimization impact analyses
    #     Ex. Public function that could be declared external, which could affect gas cost
    # These tend to report noisy results
    # https://github.com/crytic/slither#detectors lists the detectors
    # the bottom ones are informational/optimzation detectors (see impact column)
    SLITHER_CMD = 'slither . --json - --exclude-informational --exclude-optimization'.freeze

    def should_run?
      # only support truffle/hardhat for now
      return false if !@repository.package_json_present? || !has_package_config

      @repository.sol_file_present? != false
    end

    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def run
      # Most Solidity projects will be Hardhat (https://hardhat.org/) or Truffle (https://trufflesuite.com/),
      # which both use NPM to manage Solidity dependencies. We should NPM install in these cases
      # to ensure Slither has the needed dependencies for scanning

      pre_slither_commands = ['npm install', 'npm config set user 0']
      pre_slither_commands.each do |pcmd|
        shell_return = run_shell(pcmd, chdir: @repository.path_to_repo)
        if !shell_return.success?
          err_msg = pcmd + ' failed! ' + shell_return.stderr
          report_error(err_msg)
          report_stderr(err_msg)
          return report_failure
        end
      end

      scmd = SLITHER_CMD + config_opts
      shell_return = run_shell(scmd, chdir: @repository.path_to_repo)
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

      process_parsed_output(stdout_json, shell_return)
    end

    def version
      run_shell('slither --version').stdout.rstrip
    end

    def self.supported_languages
      ['solidity']
    end

    private

    def config_opts
      opts = ''
      if @config['filter-paths'].to_s != ''
        # Note: Slither webpage says filter-paths value is either a regular path or a regex
        #       But `slither --help` says it is a comma separated list of paths, which is incorrect.
        #       A list of paths must be joined by | as in a regular expression, not comma
        #        opts += ' --filter-paths "' + @config['filter-paths'].to_s + '"'
        opts += ' --filter-paths ' + @config['filter-paths'].to_s + ''
      end
      opts
    end

    def process_parsed_output(stdout_json, shell_return)
      if !stdout_json['success'] || !stdout_json['error'].nil? ||
          stdout_json['results'].nil? || stdout_json['results']['detectors'].nil?
        err_msg = 'Error extracting slither output: ' + shell_return.inspect
        report_error(err_msg)
        report_stderr(err_msg)
      else
        results = []
        stdout_json['results']['detectors'].each do |r|
          result = {}
          %w[description check impact confidence].each do |k|
            result[k] = r[k]
          end
          result['location'] = r['first_markdown_element']
          # slither json does not include reference urls
          # result['ref_url'] tag is not defined for all checks
          # if undefined, then the url will point to the top of the main documentation page
          result['ref_url'] = REF_URL_PREFIX + result['check']
          results.push(result)
        end
        report_stdout(JSON.pretty_generate(results))
        log(JSON.pretty_generate(results))
      end
    end

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
