require 'salus/scanners/base'

# Report Cocoapod usage

module Salus::Scanners
  class ReportPodfileLock < Base
    class ReportPodfileLockError < StandardError; end

    def run
      begin
        parser = Salus::PodlockDependencyParser.new(@repository.podfile_lock_path)
        parser.parse
        if parser.podlock_dependencies.empty?
          err_msg = "No dependencies found in Podfile.lock!"
          raise StandardError, err_msg
        end
      rescue StandardError => e
        report_stderr(e.message)
        report_error(e.message)
        return
      end

      parser.podlock_dependencies.each do |dependency|
        report_dependency(
          'Podfile.lock',
          type: 'cocoapods',
          name: dependency['pod'],
          version: dependency['version']
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
