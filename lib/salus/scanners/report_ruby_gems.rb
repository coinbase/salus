require 'salus/scanners/base'

# Report the use of any Ruby gems.

module Salus::Scanners
  class ReportRubyGems < Base
    def run
      # A lockfile is the most definitive source of truth for what will run
      # in production. It also lists the dependencies of dependencies.
      # We preference parsing the Gemfile.lock over the Gemfile.
      if @repository.gemfile_lock_present?
        record_dependencies_from_gemfile_lock
      elsif @repository.gemfile_present?
        record_dependencies_from_gemfile
      else
        raise InvalidScannerInvocationError,
              'Cannot report on Ruby gems without a Gemfile or Gemfile.lock'
      end
    end

    def should_run?
      @repository.gemfile_present? || @repository.gemfile_lock_present?
    end

    private

    def record_dependencies_from_gemfile_lock
      lockfile = Bundler::LockfileParser.new(@repository.gemfile_lock)

      # N.B. lockfile.bundler_version is a Gem::Version
      report_info(:ruby_version, lockfile.ruby_version)
      report_info(:bundler_version, lockfile.bundler_version.to_s)

      lockfile.specs.each do |gem|
        record_ruby_gem(
          name: gem.name,
          version: gem.version.to_s,
          source: gem.source.to_s,
          dependency_file: 'Gemfile.lock'
        )
      end
    end

    def record_dependencies_from_gemfile
      ruby_project = Bundler::Definition.build("#{@repository.path_to_repo}/Gemfile", nil, nil)

      # Record ruby version if present in Gemfile.
      if ruby_project.ruby_version
        ruby_version = ruby_project.ruby_version.versions.first
        report_info(:ruby_version, ruby_version)
      end

      # Record ruby gems.
      ruby_project.dependencies.each do |gem|
        record_ruby_gem(
          name: gem.name,

          # For a Gemfile, the best estimation of the version is the requirement.
          version: gem.requirement.to_s,

          # Gem uses the given source, otherwise Bundler has a default.
          source: gem.source.nil? ? Bundler.rubygems.sources.first.uri.to_s : gem.source.to_s,

          dependency_file: 'Gemfile'
        )
      end
    end

    def record_ruby_gem(name:, version:, source:, dependency_file:)
      report_dependency(
        dependency_file,
        type: 'gem',
        name: name,
        version: version,
        source: source
      )
    end
  end
end
