require 'salus/scanners/base'

# Report Java library usage

module Salus::Scanners
  class ReportGradleDeps < Base
    EMPTY_STRING = "".freeze

    def run
      content = File.read(@repository.gradle_lockfile_path)
      content.each_line do |line|
        parts = line.split(":")
        group_id = parts[0]
        artifact_id = parts[1]
        report_dependency(
          'gradle.lockfile',
          type: 'gradle',
          name: artifact_id.nil? ? group_id : "#{group_id}/#{artifact_id}",
          version: if parts[2].include?("=")
                     parts[2].split("=")[0]
                   else
                     EMPTY_STRING
                   end
        )
      end
    end

    def should_run?
      @repository.gradle_lockfile_present?
    end

    def self.supported_languages
      ['java']
    end
  end
end
