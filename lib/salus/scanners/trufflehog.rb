require 'json'
require 'salus/scanners/base'

# Trufflehog scanner integration. Flags secrect present in the repo.
# https://github.com/trufflesecurity/trufflehog

# TOOD Create a SARIF adapter in lib/sarif
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
      #      "trufflehog filesystem --directory=. --only-verified --json"
      "trufflehog filesystem --directory=. --json"
    end

    def run
      shell_return = run_shell(command, chdir: @repository.path_to_repo)

      # truffle hog returns success status even if vulnerabilities are dectecd
      # it writes vulnerabilities to stdout
      
      return report_success if shell_return.success? && shell_return.stderr.empty? && shell_return.stdout.empty?

      report_failure

      if !shell_return.success? || shell_return.stdout.empty?
        err = "TruffleHog exited unexpectedly. Stderr = #{shell_return.stderr}. Stdout = #{shell_return.stdout}"
        report_error(
          status: shell_return.status,
          error: err
        )
        report_stderr(err)
      else
        # each line in stdout is a separate vulnerability json
        vulns = shell_return.stdout.split("\n")
        parsed_vulns = []
        err = ''
        vulns.each do |v|
          begin
            parsed_v = JSON.parse(v)
            filtered_v = {}
            filtered_v['Leaked Credential'] = parsed_v['Raw']
            filtered_v['File'] = parsed_v.dig('SourceMetadata', 'Data', 'Filesystem', 'file')
            filtered_v['Detector Name'] = parsed_v['DetectorName']
            filtered_v['Decoder Name'] = parsed_v['DecoderName']
            filtered_v['Verified'] = parsed_v['Verified']
            parsed_vulns.push filtered_v                       
          rescue StandardError => e
            err += "Unable to parse #{v}, error = #{e.inspect}\n"
          end
        end
        err += "No vulnerabilities found in stdout" if parsed_vulns.empty?
        if !err.empty?
          report_error(error: err)
          report_stderr(err)
          return
        end
        
        log("Truffle hog detected these leaked secrets: \n" + JSON.pretty_generate(parsed_vulns))
      end
    end
  end
end
