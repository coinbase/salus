require 'salus/scanners/base'

# Report Cocoapod usage

module Salus::Scanners
  class ReportPodfileLock < Base
    def run
      shell_return =
        run_shell("bin/parse_podfile_lock #{@repository.path_to_repo}/Podfile.lock", chdir: nil)

      if !shell_return.success?
        report_error(shell_return.stderr)
        return
      end

      dependencies = nil
      begin
        dependencies = JSON.parse(shell_return.stdout)
      rescue JSON::ParserError
        err_msg = "Could not parse JSON returned by bin/parse_podfile_lock's stdout!"
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end

      dependencies.each do |dependency|
        pod = dependency['pod']
        version = dependency['version']
        report_dependency(
          'Podfile.lock',
          type: 'cocoa',
          name: pod,
          version: version
        )
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
