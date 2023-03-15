require 'digest'
require 'json'
require 'salus/scanners/base'

# Trufflehog scanner integration. Flags secrect present in the repo.
# https://github.com/trufflesecurity/trufflehog

module Salus::Scanners
  class Trufflehog < Base
    def should_run?
      true
    end

    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def version
      shell_return = run_shell('trufflehog --version')
      # stdout looks like "trufflehog 3.18.0\n"
      # for some reason, truffle hog writes version to stderr, not stdout
      shell_return.stderr&.split&.dig(1).to_s
    end

    def self.supported_languages
      ['*']
    end

    def command
      cmd = "trufflehog filesystem --json --no-update ."
      # default to true
      if @config['only-verified'].to_s == 'true' || @config['only-verified'].to_s == ''
        cmd += ' --only-verified'
      end
      cmd
    end

    def run
      shell_return = run_shell(command, chdir: @repository.path_to_repo)

      # truffle hog returns success status even if vulnerabilities are detected
      # it writes vulnerabilities to stdout

      if shell_return.success? && shell_return.stderr.empty? && shell_return.stdout.empty?
        return report_success
      end

      report_failure

      if !shell_return.success? || shell_return.stdout.empty? || !shell_return.stderr.empty?
        err = "Error running TruffleHog. Stderr = #{shell_return.stderr}. " \
              "Stdout = #{shell_return.stdout}"
        report_error(
          status: shell_return.status,
          error: err
        )
        report_stderr(err)
      else
        # each line in stdout is a separate vulnerability json
        exception_ids = Set.new(fetch_exception_ids)
        vulns = shell_return.stdout.split("\n")
        parsed_vulns = []
        err = ''
        vulns.each do |v|
          parsed_v = JSON.parse(v)
          id = parsed_v['DetectorName'] + '-' + parsed_v['DecoderName']
          if !exception_ids.include?(id)
            filtered_v = {}
            raw_credential = parsed_v['Raw']
            filtered_v['SHA256 of Leaked Credential'] = Digest::SHA256.hexdigest(raw_credential)
            filtered_v['File'] = parsed_v.dig('SourceMetadata', 'Data', 'Filesystem', 'file')
            filtered_v['Line Num'] = line_num(filtered_v['File'], raw_credential)
            filtered_v['ID'] = id
            filtered_v['Verified'] = parsed_v['Verified']
            parsed_vulns.push filtered_v
          end
        rescue StandardError => e
          err += "Unable to parse #{v}, error = #{e.inspect}\n"
        end

        if !err.empty?
          report_error(error: err)
          report_stderr(err)
          return
        end
        return report_success if parsed_vulns.empty?

        log(JSON.pretty_generate(parsed_vulns))
      end
    end

    def line_num(file, secret)
      file = File.join(@repository.path_to_repo, file)
      File.readlines(file).each_with_index do |line, line_index|
        return line_index + 1 if line.include?(secret)
      end
      1
    end
  end
end
