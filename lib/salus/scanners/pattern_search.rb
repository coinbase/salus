require 'salus/scanners/base'

# Report any matches to a list of regexs provided by the config file.
# We will actually use sift, a superior grep like tool.
# Config file can provide:
#   - exclude_directories: Array of directories (GLOB) in the repo to exclude from the search.
#   - exclude_extensions: Array of file extensions to exclude from the search.
#   The above can also be provided per-match, and will override the global values.
#   - matches: Array[Hash]
#       regex:       <regex>   (required)      regex to match against.
#       forbidden:   <boolean> (default false) if true, a hit on this regex will fail the test.
#       required:    <boolean> (default false) if true, the absense of this pattern is a failure.
#       message:     <string>  (default '')    custom message to display among failure.

module Salus::Scanners
  class PatternSearch < Base
    def run
      global_exclude_directory_flags = flag_list('--exclude-dirs', @config['exclude_directory'])
      global_exclude_extension_flags = extension_flag(@config['exclude_extension'])

      # For each pattern, keep a running history of failures, errors, and hits
      # These will be reported on at the end.
      failure_messages = []
      errors = []
      all_hits = []

      Dir.chdir(@repository.path_to_repo) do
        @config['matches']&.each do |match|
          # Sift has the following behavior:
          #   - if something found: return 0, report each hit to STDOUT - 1 per line.
          #   - if nothing found:   return 1, no STDOUT or STDERR
          #   - if error:           return 1, STDERR has the error
          #   - if panic:           return 2, STDERR has the error

          match_exclude_directory_flags = flag_list(
            '--exclude-dirs', match['exclude_directory']
          )
          match_exclude_extension_flags = extension_flag(match['exclude_extension'])

          command_string = [
            "sift -n -e \"#{match['regex']}\" .",
            match_exclude_directory_flags || global_exclude_directory_flags,
            match_exclude_extension_flags || global_exclude_extension_flags
          ].compact.join(' ')
          shell_return = run_shell(command_string)

          # Set defaults.
          match['forbidden'] ||= false
          match['required'] ||= false
          match['message'] ||= ''

          if shell_return.success? # hit
            if match['forbidden']
              failure_messages << "Forbidden pattern \"#{match['regex']}\" was found " \
                "- #{match['message']}"
            end

            hits = shell_return.stdout.encode(
              "utf-8",
              invalid: :replace,
              undef: :replace
            ).split("\n")

            hits.each do |hit|
              all_hits << {
                regex: match['regex'],
                forbidden: match['forbidden'],
                required: match['required'],
                msg: match['message'],
                hit: hit
              }
            end

          elsif [1, 2].include?(shell_return.status)
            if shell_return.stderr.empty?
              # If there were no hits, but the pattern was required add an error message.
              if match['required']
                failure_messages << "Required pattern \"#{match['regex']}\" was not found " \
                  "- #{match['message']}"
              end
            else
              errors << { status: shell_return.status, stderr: shell_return.stderr }
            end
          else
            raise UnhandledExitStatusError,
                  "Unknown exit status #{shell_return.status} from sift "\
                    "(grep alternative).\n" \
                    "STDOUT: #{shell_return.stdout}\n" \
                    "STDERR: #{shell_return.stderr}"
          end
        end
      end

      report_info(:hits, all_hits)
      errors.each { |error| report_error('Call to sift failed', error) }
      failure_messages.each { |message| report_error(message) }

      if errors.empty? && failure_messages.empty?
        report_success
      else
        report_failure
      end
    end

    def should_run?
      true # we will always run this on the provided folder
    end

    private

    def extension_flag(file_extensions)
      if file_extensions.nil?
        nil
      elsif file_extensions.empty?
        ""
      else
        flag = '--exclude-ext='
        flag << file_extensions.join(',')
      end
    end

    # returns nil if list is nil
    def flag_list(flag, list)
      list&.map do |value|
        "#{flag}=#{value}"
      end&.join(' ')
    end
  end
end
