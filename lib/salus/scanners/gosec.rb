require 'salus/scanners/base'
require 'json'

# Gosec scanner check Go for insecure coding patters.
# https://github.com/securego/gosec

module Salus::Scanners
  class Gosec < Base
    def run
      # Shell Instructions:
      #   - -fmt=json for JSON output
      #   - gosec can scan go modules as of 2.0.0.
      shell_return = Dir.chdir(@repository.path_to_repo) do
        # sometimes the go.sum needs to be forced updated to be able to correctly build packages.
        # forcing go get seems to do the trick
        if File.size?('go.mod')
          go_get_ret = run_shell("go get ./...")
          if go_get_ret.status != 0
            go_get_err = "Unable to start gosec because go get ./... failed. #{go_get_ret.stderr}"
            report_error(go_get_err, status: go_get_ret.status)
            report_stderr(go_get_err)
            return report_failure
          end
        end
        cmd = "gosec #{config_options}-fmt=json ./..."
        run_shell(cmd)
      end

      # This produces no JSON output so must be checked before parsing stdout
      if shell_return.stdout.blank? && shell_return.stderr.include?('No packages found')
        report_error(
          '0 lines of code were scanned',
          status: shell_return.status
        )
        report_stderr(shell_return.stderr)
        return report_failure
      end

      shell_return_json = JSON.parse(shell_return.stdout)
      lines_scanned = shell_return_json['Stats']['lines']  # number of lines scanned
      golang_errors = shell_return_json['Golang errors']   # a hash of compile errors
      found_issues = shell_return_json['Issues'] # a list of found issues

      # Gosec's Logging Behavior:
      #   - no vulns found - status 0, logs to STDERR and STDOUT
      #   - vulns found    - status 1, logs to STDERR and STDOUT
      #   - build error    - status 1, logs to STDERR only
      return report_success if shell_return.success? && lines_scanned.positive?

      report_failure
      if shell_return.status == 1 && (!golang_errors.empty? || !found_issues.empty?)
        report_stdout(shell_return.stdout)
        log(shell_return.stdout)
      elsif lines_scanned.zero?
        report_error(
          "0 lines of code were scanned",
          status: shell_return.status
        )
        report_stderr(shell_return.stderr)
      else
        report_error(
          "gosec exited with build error: #{shell_return.stderr}",
          status: shell_return.status
        )
        report_stderr(shell_return.stderr)
      end
    end

    # flag options taken from https://github.com/securego/gosec/blob/2.0.0/cmd/gosec/main.go
    def config_options
      lmh_regex = /\Alow|medium|high\z/i
      build_options(
        prefix: '-',
        suffix: ' ',
        separator: '=',
        args: {
          nosec: :bool, # Ignores #nosec comments when set
          'nosec-tag': /\A\S+\z/, # Set an alternative string for #nosec
          include: { # Comma separated list of rules IDs to include
            type: :list,
            regex: /\AG\d{3}\z/i
          },
          exclude: { # Comma separated list of rules IDs to exclude
            type: :list,
            regex: /\AG\d{3}\z/i
          },
          sort: :bool, # Sort issues by severity
          # Filter out the issues with a lower severity than the given value.
          # Valid options are: low, medium, high
          severity: lmh_regex,
          # Filter out the issues with a lower confidence than the given value.
          # Valid options are: low, medium, high
          confidence: lmh_regex,
          'no-fail': :bool, # Do not fail the scanning, even if issues were found
          tests: :bool, # Scan tests files
          # exlude the folders from scan
          # can be files or directories
          'exclude-dir': :file
        }
      )
    end

    def should_run?
      # Check go filetypes that tend to be present at top level directory.
      @repository.dep_lock_present? ||
        @repository.go_mod_present? ||
        @repository.go_sum_present? ||
        go_file?
    end

    def go_file?
      !Dir.glob("#{@repository.path_to_repo}/**/*.go").first.nil?
    end
  end
end
