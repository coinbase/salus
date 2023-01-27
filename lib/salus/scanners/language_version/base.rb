require 'salus/scanners/base'
require 'json'

module Salus::Scanners::LanguageVersion
  class Base < Salus::Scanners::Base
    class SemVersion < Gem::Version; end

    WARN = "warn".freeze
    ERROR = "error".freeze
    MIN = "min".freeze
    MAX = "max".freeze
    MIN_VERSION = "min_version".freeze
    MAX_VERSION = "max_version".freeze

    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def run
      # return error if language version not found
      if lang_version.nil?
        error_msg = "Please supply the path to a " \
                    "#{self.class.supported_languages[0]} application"
        return report_error(error_msg)
      end

      if !(@config.key?(WARN) || @config.key?(ERROR))
        error_msg = "Incorrect #{WARN} or #{ERROR} configuration found for scanner."
        return report_error(error_msg)
      elsif @config.dig(WARN)
        unless !@config.dig(WARN, MIN_VERSION).nil? || !@config.dig(WARN, MAX_VERSION).nil?
          error_msg = "Incorrect #{WARN} configuration found for scanner."
          return report_error(error_msg)
        end
      elsif @config.dig(ERROR)
        unless !@config.dig(ERROR, MIN_VERSION).nil? || !@config.dig(ERROR, MAX_VERSION).nil?
          error_msg = "Incorrect #{ERROR} configuration found for scanner."
          return report_error(error_msg)
        end
      end

      # check rules
      errors = []
      warns = []
      warns = check_rules(@config[WARN], WARN) if @config.key?(WARN)
      errors = check_rules(@config[ERROR], ERROR) if @config.key?(ERROR)

      # combine warns and errors
      results = []
      results.concat(warns)
      results.concat(errors)

      return report_success if errors.empty?

      report_failure
      log(JSON.pretty_generate(results))
    end

    def check_rules(config, type)
      violations = []
      version = SemVersion.new(lang_version)
      min_version = SemVersion.new(config[MIN_VERSION]) if config[MIN_VERSION]
      max_version = SemVersion.new(config[MAX_VERSION]) if config[MAX_VERSION]

      if min_version && (version < min_version)
        violations.append(warn_message(version, min_version, MIN)) if type == WARN
        violations.append(error_message(version, min_version, MIN)) if type == ERROR
      end

      if max_version && (version > max_version)
        violations.append(warn_message(version, max_version, MAX)) if type == WARN
        violations.append(error_message(version, max_version, MAX)) if type == ERROR
      end

      violations
    end

    def warn_message(version, target, type)
      if type == MIN
        "Warn: Repository language version (#{version}) is less " \
          "than minimum recommended version (#{target}). " \
          "It is recommended to upgrade the language version."
      else
        "Warn: Repository language version (#{version}) is greater " \
          "than maximum recommended version (#{target}). " \
          "It is recommended to downgrade the language version."
      end
    end

    def error_message(version, target, type)
      if type == MIN
        "Error: Repository language version (#{version}) is less " \
          "than minimum recommended version (#{target}). " \
          "Please upgrade the language version."
      else
        "Error: Repository language version (#{version}) is greater " \
          "than maximum recommended version (#{target}). " \
          "Please downgrade the language version."
      end
    end

    def name
      self.class.name.sub('Salus::Scanners::LanguageVersion::', '')
    end

    def should_run?
      run_version_scan?
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
