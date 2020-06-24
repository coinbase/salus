require "salus/scanners/base"
require "json"

# Report any matches to a list of semantic grep patterns provided by the config file.
# semgrep is a grep like tool for doing AST pattern matching.
# See https://semgrep.dev for more info and documentation.
# Config file can provide:
#   - exclude_directories: Array of directories in the repo to exclude from the search.
#   - language: A global language flag if you don't want to set it per pattern.
#   The above can also be provided per-pattern, and will override the global values.
#   - matches: Array[Hash]
#                                              External Semgrep Config:
#       config:      <string>  (required)      config string to pass to semgrep.
#
#                                              Simple Pattern: (Required if `config` not defined)
#       pattern:     <string>  (required)      pattern to match against.
#       language:    <string>  (required)      language the pattern is written in.
#
#       forbidden:   <boolean> (default false) if true, a hit on this pattern will fail the test.
#       required:    <boolean> (default false) if true, the absense of this pattern is a failure.
#       message:     <string>  (default '')    custom message to display among failure.

module Salus::Scanners
  class Semgrep < Base
    def run
      global_exclude_directory_flags = flag_list('--exclude-dir', @config['exclude_directory'])

      # For each pattern, keep a running history of failures, errors, warnings, and hits
      # These will be reported on at the end.
      failure_messages = []
      warning_messages = []
      errors = []
      warnings = []
      all_hits = []

      Dir.chdir(@repository.path_to_repo) do
        base_path = Dir.pwd
        @config["matches"]&.each do |match|
          # semgrep has the following behavior:
          #   ouputs a json object with a 'results' and 'errors' key

          if !match['config'].nil?
            override_keys = %w[pattern language message]
            override_keys.any? do |k|
              if match.keys.include?(k)
                err_msg = "[#{override_keys.join(', ')}] cannot be specified in both
                           salus.yaml and -config semgrep_rule_file"
                report_error(err_msg)
                report_stderr(err_msg)
                return report_failure
              end
            end
          end

          # Set defaults.
          match["forbidden"] ||= false
          match["required"] ||= false
          match["strict"] ||= false
          match["message"] ||= ""

          pattern_exclude_directory_flags = flag_list(
            '--exclude-dir', match['exclude_directory']
          )

          command, user_message = build_command_and_message(
            match,
            @config['strict'] || match["strict"],
            base_path,
            pattern_exclude_directory_flags || global_exclude_directory_flags
          )
          # run semgrep
          shell_return = run_shell(command)
          # check to make sure it's successful
          if shell_return.success?
            # parse the output
            data = JSON.parse(shell_return.stdout)
            hits = data["results"]
            semgrep_non_fatal_errors = data["errors"]
            semgrep_non_fatal_errors&.map do |nfe|
              nfe_str = error_to_string(nfe)
              warning_messages << nfe_str
              warnings << {
                message: nfe_str,
                details: error_to_object(nfe)
              }
            end

            if hits.empty?
              # If there were no hits, but the pattern was required add an error message.
              if match["required"]
                failure_messages << "Required #{user_message} was not found " \
                "- #{match['message']}"
              end
            else
              hits.each do |hit|
                msg = message_from_hit(hit, match)
                if match["forbidden"]
                  failure_messages << "Forbidden #{user_message} was found " \
                  "- #{msg}\n" \
                  "\t#{hit_to_string(hit, base_path)}"
                end
                all_hits << {
                  pattern: match['pattern'],
                  config: match['config'],
                  forbidden: match["forbidden"],
                  required: match["required"],
                  msg: msg,
                  hit: hit_to_string(hit, base_path)
                }
              end
            end

          # possible exit codes from https://github.com/returntocorp/semgrep/blob/9ac58092cb8ac02bb1f41f59808d4f03a5b8206e/semgrep/semgrep/util.py#L11-L18
          elsif [1, 2, 3, 4, 5, 6, 7].include?(shell_return.status)
            if match['required']
              failure_messages << "Required #{user_message} was not found " \
                "- #{match['message']}"
            end
            begin
              # parse the output
              output_data = JSON.parse(shell_return.stdout)
              error_str = messages_str_from_errors(output_data["errors"])
              # only take the first line of stderror because the other lines
              # are verbose debugging info generated based on a temp file
              # so the filename is random and fails the test.
              errors << {
                status: shell_return.status,
                stderr: shell_return.stderr.split("\n").first \
                + "\n\n" + error_str
              }
            rescue JSON::ParserError
              # only take the first line of stderror because the other lines
              # are verbose debugging info generated based on a temp file
              # so the filename is random and fails the test.
              errors << {
                status: shell_return.status,
                stderr: shell_return.stderr.split("\n").first
              }
            end
          else
            # only take the first line of stderror because the other lines
            # are verbose debugging info generated based on a temp file
            # so the filename is random and fails the test.
            raise UnhandledExitStatusError,
                  "Unknown exit status #{shell_return.status} from semgrep.\n" \
                  "STDOUT: #{shell_return.stdout}\n" \
                  "STDERR: #{shell_return.stderr.split("\n").first}\n"
          end
        end

        report_info(:hits, all_hits)
        errors.each { |error| report_error("Call to semgrep failed", error) }
        report_warn(:semgrep_non_fatal, warnings) unless warnings.empty?
        warning_messages.each { |message| log(message) }

        if failure_messages.empty?
          report_success
        else
          report_failure
          failure_messages.each { |message| log(message) }
        end
      end
    end

    def should_run?
      true # we will always run this on the provided folder
    end

    def build_command_and_message(match, strict, base_path, exclude_directories_flags)
      has_external_config = !match['config'].nil?
      strict_flag = strict ? '--strict' : nil

      if has_external_config
        config = match['config']
        command = [
          "semgrep",
          strict_flag,
          "--json",
          "--config",
          File.join(base_path, config),
          *exclude_directories_flags,
          base_path
        ].compact
        user_message = "patterns in config \"#{config}\""
      else
        pattern = match['pattern']
        command = [
          "semgrep",
          strict_flag,
          "--json",
          "--pattern",
          pattern,
          "--lang",
          match['language'],
          *exclude_directories_flags,
          base_path
        ].compact
        user_message = "pattern \"#{pattern}\""
      end

      [command, user_message]
    end

    def message_from_hit(hit, match)
      has_external_config = !match['config'].nil?
      msg = if has_external_config
              hit['extra']['message']
            else
              match['message']
            end
      msg
    end

    # returns nil if list is nil
    def flag_list(flag, list)
      list&.map do |value|
        "#{flag}=#{value}"
      end
    end

    def hit_to_string(hit, base_path)
      "#{hit['path'].sub(base_path + '/', '')}:#{hit['start']['line']}:" \
        "#{hit['extra']['lines']}".rstrip
    end

    def error_to_object(err)
      data = err.fetch('data', {})
      path = data.fetch('path', 'no path')
      start = data.fetch('start', {})
      end_obj = data.fetch('end', {})
      extra = data.fetch('extra', {})
      message = extra.fetch('message', 'no message')
      line = extra.fetch('line', '')
      {
        path: path,
        start: start,
        end: end_obj,
        message: message,
        line: line
      }
    end

    def error_to_string(err)
      err_obj = error_to_object(err)
      "#{err_obj[:message]}\n\t#{err_obj[:path]}:#{err_obj[:start].fetch('line', '')}"
    end

    def messages_str_from_errors(list_of_errors)
      list_of_errors&.map do |err|
        error_to_string(err)
      end&.join("\n")
    end
  end
end
