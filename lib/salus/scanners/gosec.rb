require 'salus/scanners/base'
require 'json'

# Gosec scanner check Go for insecure coding patters.
# https://github.com/securego/gosec

module Salus::Scanners
  class Gosec < Base

    # *  run gosec ./... from each directory that contains a go dependency file
    #    each time gosec runs, exclude all subdirs that contain dependency file
    #
    # *  salus.yaml may contain exclude-dir, which are paths relative to the top-level dir
    #    when running subdir, each exclude-dir path from salus.yaml must be either
    #       1) removed if exclude-dir path does not reside in subdir
    #       2) updated to a path relative to the subdir
    #
    # *  go dependency file = go.mod / go.sum / Gopkg.lock
    def run
      go_dirs = []                # list of dirs to run gosec run
      salus_yaml_ex_dir = nil     # original list of exclude-dir values in salus.yaml
      repo_prefix = @repository.path_to_repo
      @gosec_failed = false

      # remove trailing / from directories specified by exclude-dir in salus.yaml
      if @config['exclude-dir']
        @config['exclude-dir'].map! {|d| d.end_with?('/') ? d.delete_suffix('/') : d}
        salus_yaml_ex_dir = @config['exclude-dir'].freeze
      end

      # get all directories containing go dependency files
      Dir.chdir(@repository.path_to_repo) do
        go_dirs = go_dep_dirs()
        # gosec ignores vendor dirs
        go_dirs.delete_if do |d|
          d.start_with?('vendor/') || d.include?('/vendor/') || d == 'vendor'
        end
      end

      if go_dirs.empty?
        report_stderr("There is no go.mod / go.sum / Gopkg.lock in your repo")
        return report_failure
      end


      # remove directories that are specified by exclude-dirs in salus.yaml
      go_dirs -= salus_yaml_ex_dir if salus_yaml_ex_dir

      go_dirs.each do |d|
        @repository.instance_variable_set(:@path_to_repo, repo_prefix + '/' + d)
        ex_dirs = []
        @config['exclude-dir'] = []

        # for each dir in salus.yaml exclude-dir
        # if dir is a subdir in the current go_dir
        # update the exclude-dir path to be relative to the subdir
        # Ex. if --exclude-dir = subdir/subdir2 and gosec runs from subdir
        #     then update --exclude-dir = subdir2
        if salus_yaml_ex_dir
          salus_yaml_ex_dir.each do |e|
            repo_rel_path = repo_prefix + '/' + e
            if repo_rel_path.start_with?(@repository.path_to_repo + '/')
              ex_path = repo_rel_path.delete_prefix(@repository.path_to_repo + '/')
              @config['exclude-dir'].push(ex_path)
            end
          end
        end

        # exclude subdirs containing go dependency files
        go_dep_subdirs = []
        Dir.chdir(@repository.path_to_repo) do
          go_dep_subdirs = go_dep_dirs('*/**')
        end

        @config['exclude-dir'] += go_dep_subdirs if !go_dep_subdirs.empty?
        @config.delete('exclude-dir') if @config['exclude-dir'].empty?

        run_gosec
        report_failure if @gosec_failed
      end
    end
    
    def run_gosec
      
      # Shell Instructions:
      #   --fmt=json for JSON output
      shell_return = Dir.chdir(@repository.path_to_repo) do
        cmd = "gosec #{config_options}-fmt=json ./..."
        run_shell(cmd)
      end
      
      # This produces no JSON output so must be checked before parsing stdout
      if shell_return.stdout.blank? && shell_return.stderr.include?('No packages found')
        @gosec_failed = true
        report_error(
          "0 lines of code were scanned in #{@repository.path_to_repo}",
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

      @gosec_failed = true      
      report_failure
      if shell_return.status == 1 && (!golang_errors.empty? || !found_issues.empty?)
        shell_return_stdout_json =  JSON.parse(shell_return.stdout)
        shell_return_stdout_json["Directory"] = @repository.path_to_repo
        shell_return_stdout = JSON.pretty_generate(shell_return_stdout_json)
        report_stdout(shell_return_stdout)
        log(shell_return_stdout)

#        report_error(shell_return_stdout, status: shell_return.status)
 #       report_stderr(shell_return_stdout)
        

#        report_stdout(shell_return.stdout)
#        log(shell_return.stdout)
      elsif lines_scanned.zero?
        report_error(
          "0 lines of code were scanned in #{@repository.path_to_repo}",
          status: shell_return.status
        )
        report_stderr(shell_return.stderr)
      else
        report_error(
          "gosec exited with build error in #{@repository.path_to_repo}: #{shell_return.stderr}",
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

    # directories containing go dependency files
    def go_dep_dirs(prefix='**')
      dep_files = ['go.mod', 'go.sum', 'Gopkg.lock']
      dirs = []
      dep_files.each do |dep_file|
        new_dirs = Dir.glob(prefix + '/' + dep_file).map {|f| File.dirname(f)}
        dirs.concat(new_dirs)
      end
      dirs.uniq
    end

    def go_file?
      !Dir.glob("#{@repository.path_to_repo}/**/*.go").first.nil?
    end
  end
end
