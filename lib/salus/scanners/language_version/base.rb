require 'salus/scanners/base'
require 'json'

module Salus::Scanners::LanguageVersion
  class Base < Salus::Scanners::Base
    class SemVersion < Gem::Version; end

    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def run
      if lang_version.nil?
        error_msg = "Please supply the path to a " \
                    "#{self.class.supported_languages[0]} application"
        return report_error(error_msg)
      end

      version = SemVersion.new(lang_version)
      min_version = SemVersion.new(@config['min_version']) if @config['min_version']
      max_version = SemVersion.new(@config['max_version']) if @config['max_version']

      if min_version && (version < min_version)
        error_msg = "Repository language version (#{version}) is less " \
        "than minimum configured version (#{min_version})"
        report_error(error_msg)
        return report_failure
      end

      if max_version && (version > max_version)
        error_msg = "Repository language version (#{version}) is greater " \
        "than maximum configured version (#{max_version})"
        report_error(error_msg)
        return report_failure
      end

      report_success
    end

    def name
      self.class.name.sub('Salus::Scanners::LanguageVersion::', '')
    end

    def should_run?
      configured_version_present = !@config['min_version'].nil? || !@config['max_version'].nil?
      configured_version_present && run_version_scan?
    end

    private

    def run_version_scan?
      raise NoMethodError
    end

    def lang_version
      raise NoMethodError
    end
  end
end
