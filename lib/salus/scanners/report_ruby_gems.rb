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
        raise NotImplementedError,
              'Cannot report on Ruby gems without a Gemfile or Gemfile.lock'
      end
    end

    def should_run?
      @repository.gemfile_present? || @repository.gemfile_lock_present?
    end

    private

    def record_dependencies_from_gemfile_lock
      lockfile = Bundler::LockfileParser.new(@repository.gemfile_lock)
      record_ruby_version(lockfile.ruby_version, 'Gemfile')
      record_bundler_version(lockfile.bundler_version, 'Gemfile')
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
        record_ruby_version(ruby_project.ruby_version.versions.first, 'Gemfile')
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

    def record_ruby_version(version, dependency_file)
      record_dependency_info({ type: 'ruby', version: version }, dependency_file)
    end

    def record_bundler_version(version, dependency_file)
      record_dependency_info({ type: 'bundler', version: version }, dependency_file)
    end

    def record_ruby_gem(name:, version:, source:, dependency_file:)
      record_dependency_info(
        {
          type: 'gem',
          name: name,
          version: version,
          source: source
        },
        dependency_file
      )
    end
  end
end
