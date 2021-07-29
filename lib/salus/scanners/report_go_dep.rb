require 'toml'
require 'salus/scanners/base'

# Report the use of Go packages captured in a Gopkg.lock files.
# https://github.com/golang/dep

module Salus::Scanners
  class ReportGoDep < Base
    def run

      if @repository.go_mod_present?
        record_dep_from_go_mod
      elsif @repository.dep_lock_present?
        record_dep_from_go_lock_package
      else
        raise(
          InvalidScannerInvocationError,
          'Cannot report on Go dependencies without a Gopkg.lock or go.mod/go.sum file'
        )
      end
    end

    def record_dep_from_go_mod
      Dir.chdir("#{@repository.path_to_repo}"){
      shell_return = run_shell("go list -json -m all")
      unless shell_return.success?
        raise ParseError, "Failed to parse go.mod file: #{shell_return.stderr}"
      end
      go_mod = JSON.parse("[#{shell_return.stdout.gsub(/\}.*?\{/m, '},{')}]")
      go_mod.each do |dependency|
        record_dep_package(
          name: dependency['Path'],
          reference: "N/A for go.mod/go.sum dependencies",
          version_tag: dependency['Version'],
          dependency_file: "go.mod",
          type: "go_mod"
        )
      end
    }
    end

    def record_dep_from_go_lock_package
      dep_lock = TOML::Parser.new(@repository.dep_lock).parsed

      # Report dependencies
      dep_lock['projects'].each do |dependency|
        record_dep_package(
          name: dependency['name'],
          reference: dependency['revision'],
          version_tag: dependency['version'],
          dependency_file: "Gopkg.lock",
          type: "go_dep_lock"
        )
      end
    end

    def self.supported_languages
      ['go']
    end

    def should_run?
      @repository.dep_lock_present? ||
      @repository.go_mod_present? ||
    end

    def record_dep_package(dependency_file:, name:, version_tag:, reference:, type:)
      report_dependency(
        dependency_file,
        type: type,
        name: name,
        reference: reference,
        version_tag: version_tag,
      )
    end

  end
end