require 'salus/scanners/base'

module Salus::Scanners
  class MisnamedConfig < Base
    def run
      if @repository.salus_yml_present?
        report_error(
          'A local file "salus.yml" was detected in the provided repository. The '\
          'correct configuration file name is "salus.yaml".'
        )
        report_failure
      else
        report_success
      end
    end

    def should_run?
      true
    end

    def self.supported_languages
      ['*']
    end
  end
end
