require 'salus/scanners/base'

# Report Java library usage

module Salus::Scanners
  class ReportBuildGradle < Base
    UNKNOWN_VERSION = ''.freeze

    def run
      shell_return =
        run_shell("bin/parse_build_gradle #{@repository.path_to_repo}/build.gradle", chdir: nil)

      if !shell_return.success?
        report_error(shell_return.stderr)
        return
      end

      dependencies = nil
      begin
        dependencies = JSON.parse(shell_return.stdout)
      rescue JSON::ParserError
        err_msg = "Could not parse JSON returned by bin/parse_build_gradle's stdout!"
        report_stderr(err_msg)
        report_error(err_msg)
        return
      end

      dependencies.each do |dependency|
        classpath = dependency['classpath']
        package_name = dependency['package']
        report_dependency(
          'build.gradle',
          type: 'gradle',
          name: "#{classpath}/#{package_name}",
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
