require 'salus/scanners/base'
require 'json'

# Gosec scanner check Go for insecure coding patterns.
# https://github.com/securego/gosec

module Salus::Scanners
  class Gosec < Base
    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def run
      # 'run_from_dirs' specifies a list of subdirs to run salus from
      # if not specified, then run_from_dir will mimic the original gosec 'run' behavior
      return run_from_dir if @config['run_from_dirs'].nil?

      @gosec_failed = false
      @gosec_stderr = '' # combined stderr on all runs (one for each configured subdir)
      @gosec_stdout = '' # ...      stdout ...
      @gosec_json = {} # combined json result on all runs
      run_from_dirs = @config['run_from_dirs'].sort
      run_from_dirs_val = @config.delete('run_from_dirs')
      run_from_dirs.each do |dir|
        if dir.start_with?("/") || dir.start_with?("./") || dir.include?("..")
          msg = "run_from_dirs values should be relative paths to subdirs in the repo " \
                "and cannot start with ./"
          report_stderr(msg)
          report_error(
            msg,
            status: 1
          )
          return report_failure
        else
          run_from_dir(dir)
        end
      end

      # gosec runs from multiple dirs
      # success only if none of the runs set @gosec_failed = true
      return report_success if @gosec_failed == false

      @config['run_from_dirs'] = run_from_dirs_val
      log(JSON.pretty_generate(@gosec_json)) if !@gosec_json.empty?
      report_stderr(@gosec_stderr) if !@gosec_stderr.empty?
      report_stdout(@gosec_stdout) if !@gosec_stdout.empty?
      report_failure
    end

    # rubocop:disable Style/IfInsideElse
    def run_from_dir(dir = nil)
      # Shell Instructions:
      #   - -fmt=json for JSON output
      work_dir = if dir
                   File.join(@repository.path_to_repo, dir)
                 else
                   @repository.path_to_repo
                 end

      cmd = "gosec #{config_options}-fmt=json ./..."
      shell_return = run_shell(cmd, chdir: work_dir)

      # This produces no JSON output so must be checked before parsing stdout
      if shell_return.stdout.blank? && shell_return.stderr.include?('No packages found')
        if dir.nil?
          report_error(
            '0 lines of code were scanned',
            status: shell_return.status
          )
          report_stderr(shell_return.stderr)
        else
          report_error(
            "0 lines of code were scanned in #{dir}",
            status: shell_return.status
          )
          @gosec_failed = true
          @gosec_stderr += shell_return.stderr + "\n"
        end
        return report_failure
      end

      shell_return_json = JSON.parse(shell_return.stdout)
      lines_scanned = shell_return_json['Stats']['lines'] # number of lines scanned
      files_scanned = shell_return_json['Stats']['files'] # number of files scanned
      num_nosec = shell_return_json['Stats']['nosec'] # number of nosec
      num_found = shell_return_json['Stats']['found'] # number found
      golang_errors = shell_return_json['Golang errors'] # a hash of compile errors
      found_issues = shell_return_json['Issues'] # a list of found issues

      # Gosec's Logging Behavior:
      #   - no vulns found - status 0, logs to STDERR and STDOUT
      #   - vulns found    - status 1, logs to STDERR and STDOUT
      #   - build error    - status 1, logs to STDERR only
      return report_success if shell_return.success? && lines_scanned.positive?

      @gosec_failed = true
      report_failure
      if shell_return.status == 1 && (!golang_errors.empty? || !found_issues.empty?)
        if dir.nil?
          report_stdout(shell_return.stdout)
          log(shell_return.stdout)
        else
          @gosec_stdout += shell_return.stdout + "\n"

          if @gosec_json == {}
            @gosec_json['Golang errors'] = {}
            @gosec_json['Issues'] = []
            @gosec_json['Stats'] = {}
            %w[files lines nosec found].each do |name|
              @gosec_json['Stats'][name] = 0
            end
          end

          @gosec_json['Issues'] += found_issues
          @gosec_json['Stats']['files'] += files_scanned
          @gosec_json['Stats']['lines'] += lines_scanned
          @gosec_json['Stats']['nosec'] += num_nosec
          @gosec_json['Stats']['found'] += num_found
          # add dir name to golang error keys
          golang_errors = golang_errors.map { |ek, ev| [dir + '/' + ek, ev] }.to_h
          @gosec_json['Golang errors'].merge!(golang_errors)
        end
      elsif lines_scanned.zero?
        if dir.nil?
          report_error(
            "0 lines of code were scanned",
            status: shell_return.status
          )
          report_stderr(shell_return.stderr)
        else
          report_error(
            "0 lines of code were scanned in #{dir}",
            status: shell_return.status
          )
          @gosec_stderr += shell_return.stderr + "\n"
        end
      else
        if dir.nil?
          report_error(
            "gosec exited with build error: #{shell_return.stderr}",
            status: shell_return.status
          )
          report_stderr(shell_return.stderr)
        else
          report_error(
            "gosec exited with build error in #{dir}: #{shell_return.stderr}",
            status: shell_return.status
          )
          @gosec_stderr += shell_return.stderr + "\n"
        end
      end
    end

    # rubocop:enable Style/IfInsideElse

    def version
      shell_return = run_shell('gosec --version')
      # stdout looks like "Version: 2.4.0\nGit tag: v2.4.0\nBuild date: 2020-07-24T07:54:54Z\n"
      shell_return.stdout&.split('\n')&.dig(0)&.split&.dig(1)
    end

    def self.supported_languages
      ['go']
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
        },
        config_overrides: { 'exclude' => excluded_ids }
      )
    end

    def excluded_ids
      (fetch_exception_ids + @config.fetch('exclude', [])).uniq
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
