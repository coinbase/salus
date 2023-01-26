require 'salus/scanners/base'
require 'json'

module Salus::Scanners::LanguageVersion
  class Base < Salus::Scanners::Base
    class SemVersion < Gem::Version; end

    INFO = "info".freeze
    BLOCK = "block".freeze
    MIN = "min".freeze
    MAX = "max".freeze

    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def run
      if lang_version.nil?
        error_msg = "Please supply the path to a " \
                    "#{self.class.supported_languages[0]} application"
        return report_error(error_msg)
      end
      results = block = info = []
      info = handle_language_version_rules(@config[INFO], INFO) if @config.key?(INFO)
      block = handle_language_version_rules(@config[BLOCK], BLOCK) if @config.key?(BLOCK)
      results.concat(info)
      results.concat(block)

      return report_success if block.empty?

      report_failure
      log(JSON.pretty_generate(results))
    end

    def handle_language_version_rules(rule, type)
      violations = []
      version = SemVersion.new(lang_version)
      min_version = SemVersion.new(rule['min_version']) if rule['min_version']
      max_version = SemVersion.new(rule['max_version']) if rule['max_version']

      violations += [
        if min_version && (version < min_version)
          if type == INFO
            info_message(version, min_version, MIN)
          elsif type == BLOCK
            block_message(version, min_version, MIN)
          end
        end,
        if max_version && (version > max_version)
          if type == INFO
            info_message(version, min_version, MAX)
          elsif type == BLOCK
            block_message(version, min_version, MAX)
          end
        end
      ]
      violations.compact
    end

    def info_message(version, target, type)
      if type == "min"
        "Info: Repository language version (#{version}) is less " \
          "than minimum recommended version (#{target}). " \
          "It is recommended to upgrade the language version."
      else
        "Info: Repository language version (#{version}) is greater " \
          "than maximum recommended version (#{target}). " \
          "It is recommended to downgrade the language version."
      end
    end

    def block_message(version, target, type)
      if type == "min"
        "Blocked: Repository language version (#{version}) is less " \
          "than minimum recommended version (#{target}). " \
          "Please upgrade the language version."
      else
        "Blocked: Repository language version (#{version}) is greater " \
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
