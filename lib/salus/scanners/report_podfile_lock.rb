require 'salus/scanners/report_base'

# Report Cocoapod usage

module Salus::Scanners
  class ReportPodfileLock < ReportBase
    class ReportPodfileLockError < StandardError; end

    def run
      shell_return =
        run_shell("bundle exec bin/parse_podfile_lock #{@repository.podfile_lock_path}", chdir: nil)

      if !shell_return.success?
        report_error(shell_return.stderr)
        return
      end

      begin
        dependencies = JSON.parse(shell_return.stdout)

        raise ReportPodfileLockError if dependencies.nil?

        dependencies.each do |dependency|
          report_dependency(
            'Podfile.lock',
            type: 'cocoapods',
            name: dependency['pod'],
            version: dependency['version']
          )
        end
      rescue ReportPodfileLockError, JSON::ParserError
        err_msg = "Could not parse JSON returned by bin/parse_podfile_lock's stdout!"
        report_stderr(err_msg)
        report_error(err_msg)
      end
    end

    def should_run?
      @repository.podfile_lock_present?
    end

    def self.supported_languages
      %w[swift objective-c]
    end
  end
end
