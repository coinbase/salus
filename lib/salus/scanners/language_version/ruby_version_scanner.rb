require 'salus/scanners/language_version/base'

module Salus::Scanners::LanguageVersion
  class RubyVersionScanner < Base
    def self.supported_languages
      %w[ruby]
    end

    private

    def run_version_scan?
      ruby_project?
    end

    def lang_version
      @lang_version ||= ruby_project? ? ruby_version : nil
    end

    def ruby_version
      return version_from_ruby_version_file if @repository.ruby_version_present?
      return version_from_gem_lock_file     if @repository.gemfile_lock_present?
      return version_from_gem_file          if @repository.gemfile_present?

      nil
    end

    # '.ruby-version' file stores the ruby version used in the ruby project
    # Following is an example for running 'cat .ruby-version':
    # 2.7.1
    def version_from_ruby_version_file
      shell_return = run_shell("cat .ruby-version")
      shell_return.nil? ? nil : shell_return.stdout
    end

    # 'Gemfile.lock' file stores the ruby version used in the ruby project
    # Following is the output for running the cmd
    # cmd: grep -A 1 RUBY Gemfile.lock
    # output: "RUBY VERSION\n   ruby 2.7.2p83\n"
    def version_from_gem_lock_file
      shell_return = run_shell("grep -A 1 RUBY Gemfile.lock")
      shell_return.nil? ? nil : shell_return.stdout.split("\n")[1].strip.split(" ")[1]
    end

    # 'Gemfile' file stores the ruby version used in the ruby project as well
    # Following is an example for running "cat Gemfile |  grep ^ruby | awk '{print $2}'":
    # '2.7.2'
    def version_from_gem_file
      shell_return = run_shell("grep ^ruby Gemfile")
      shell_return.nil? ? nil : shell_return.stdout.split(" ")[1].tr("\'", '')
    end

    def ruby_project?
      @repository.ruby_version_present? ||
        @repository.gemfile_lock_present? ||
        @repository.gemfile_present?
    end
  end
end
