require 'salus/scanners/base'

# Report Java library usage

module Salus::Scanners
  class ReportGradleDeps < Base
    def run
      begin
        parser = Salus::GradleDependencyParser.new(@repository.path_to_repo)
        parser.parse
      rescue StandardError => e
        report_stderr(e.message)
        report_error(e.message)
      end

      parser.gradle_dependencies.each do |dependency|
        group_id = dependency['group_id']
        artifact_id = dependency['artifact_id']
        report_dependency(
          'build.gradle',
          type: 'gradle',
          name: artifact_id.nil? ? group_id : "#{group_id}/#{artifact_id}",
          version: dependency['version'].nil? ? UNKNOWN_VERSION : dependency['version']
        )
      end
    end

    def should_run?
      @repository.build_gradle_present?
    end

    def self.supported_languages
      ['java']
    end
  end
end
