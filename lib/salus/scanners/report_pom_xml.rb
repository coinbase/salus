require 'salus/scanners/base'

# Report Java library usage

module Salus::Scanners
  class ReportPomXml < Base
    def run
      shell_return = run_shell("bin/parse_pom_xml #{@repository.path_to_repo}/pom.xml", chdir: nil)

      if !shell_return.success?
        report_error(shell_return.stderr)
        return
      end

      dependencies = JSON.parse(shell_return.stdout)

      dependencies.each do |dependency|
        group_id = dependency['group_id']
        artifact_id = dependency['artifact_id']
        version = dependency['version']
        report_dependency(
          'pom.xml',
          type: 'maven',
          name: "#{group_id}.#{artifact_id}",
          version: version.nil? ? 'unknown' : version
        )
      end
    end

    def should_run?
      @repository.pom_xml_present?
    end

    def self.supported_languages
      ['java']
    end
  end
end
