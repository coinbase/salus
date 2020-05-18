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
#       pattern:     <string>  (required)      pattern to match against.
#       language:    <string>  (required) language the pattern is written in.
#       forbidden:   <boolean> (default false) if true, a hit on this pattern will fail the test.
#       required:    <boolean> (default false) if true, the absense of this pattern is a failure.
#       message:     <string>  (default '')    custom message to display among failure.

module Salus::Scanners
  class Semgrep < Base
    def run
      global_exclude_directory_flags = flag_list('--exclude-dir', @config['exclude_directory'])

      # For each pattern, keep a running history of failures, errors, and hits
      # These will be reported on at the end.
      failure_messages = []
      errors = []
      all_hits = []

      Dir.chdir(@repository.path_to_repo) do
        base_path = Dir.pwd
        @config["matches"]&.each do |match|
          # semgrep has the following behavior:
          #   always returns with status code 0 if able to parse
          #   ouputs a json object with a 'results' key

          pattern_exclude_directory_flags = flag_list(
            '--exclude-dir', match['exclude_directory']
          )

          # Set defaults.
          match["forbidden"] ||= false
          match["required"] ||= false
          match["message"] ||= ""

          command = [
            "semgrep",
            "--json",
            "--pattern",
            match['pattern'],
            "--lang",
            match['language'],
            *(pattern_exclude_directory_flags || global_exclude_directory_flags),
            base_path
          ].compact

          # run semgrep
          shell_return = run_shell(command)
          # check to make sure it's successful
          if shell_return.success?
            # parse the output
            data = JSON.parse(shell_return.stdout)
            hits = data["results"]

            if hits.empty?
              # If there were no hits, but the pattern was required add an error message.
              if match["required"]
                failure_messages << "Required pattern \"#{match['pattern']}\" was not found " \
                "- #{match['message']}"
              end
            else
              hits.each do |hit|
                if match["forbidden"]
                  failure_messages << "Forbidden pattern \"#{match['pattern']}\" was found " \
                  "- #{match['message']}\n" \
                  "\t#{hit['path'].sub(base_path + '/', '')}:#{hit['start']['line']}:" \
                  "#{hit['extra']['lines']}"
                end
                all_hits << {
                  pattern: match["pattern"],
                  forbidden: match["forbidden"],
                  required: match["required"],
                  msg: match["message"],
                  hit: "#{hit['path'].sub(base_path + '/', '')}:#{hit['start']['line']}:" \
                  "#{hit['extra']['lines']}".rstrip
                }
              end
            end

          # possible exit codes from https://github.com/returntocorp/semgrep/blob/9ac58092cb8ac02bb1f41f59808d4f03a5b8206e/semgrep/semgrep/util.py#L11-L18
          elsif [1, 2, 3, 4, 5, 6, 7].include?(shell_return.status)
            if match['required']
              failure_messages << "Required pattern \"#{match['pattern']}\" was not found " \
                "- #{match['message']}"
            end
            # only take the first line of stderror because the other lines
            # are verbose debugging info generated based on a temp file
            # so the filename is random and fails the test.
            errors << { status: shell_return.status, stderr: shell_return.stderr.split("\n").first }
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

    # returns nil if list is nil
    def flag_list(flag, list)
      list&.map do |value|
        "#{flag}=#{value}"
      end
    end
  end
end
