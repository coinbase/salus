require 'salus/scanners/github_advisory/base'

module Salus::Scanners::GithubAdvisory
  class GoGithubAdvisory < Base
    class SemVersion < Gem::Version; end

    def self.supported_languages
      ['go']
    end

    def go_project?
      @repository.go_mod_present? || @repository.go_sum_present?
    end

    def run; end
  end
end
