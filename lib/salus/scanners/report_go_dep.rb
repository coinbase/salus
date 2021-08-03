require 'toml'
require 'salus/scanners/base'

# Report the use of Go packages captured in a Gopkg.lock files.
# https://github.com/golang/dep

module Salus::Scanners
  class ReportGoDep < Base
    def run
      if @repository.go_sum_present?
        record_dep_from_go_sum
      elsif @repository.go_mod_present?
        record_dep_from_go_mod
      elsif @repository.dep_lock_present?
        record_dep_from_go_lock_package
      else
        raise(
          InvalidScannerInvocationError,
          'Cannot report on Go dependencies without a Gopkg.lock, go.mod, or go.sum file'
        )
      end
    end

    def record_dep_from_go_sum
      go_sum_path = "#{@repository.path_to_repo}/go.sum"
      dep_list = []

      File.open(go_sum_path).each("=\n") do |line|
        dep_list.append({ "fullDependency" => line, "name" => get_name(line),
         "version" => get_version(line) })
      end

      dep_list.each do |dependency|
        record_dep_package(
          name: dependency['name'],
          reference: "N/A for go.mod/go.sum dependencies",
          version_tag: dependency['version'],
          dependency_file: "go.sum",
          type: "go_sum"
        )
      end
    end

    def record_dep_from_go_mod
      go_mod_path = "#{@repository.path_to_repo}/go.mod"
      dep_list = []
      parse_line = false

      File.open(go_mod_path).each("\n") do |line|
        if line.include? "require ("
          parse_line = true
        elsif line.include? ")"
          parse_line = false
        elsif parse_line
          dep_list.append({ "fullDependency" => line, "name" => get_name(line),
          "version" => get_version(line) })
        end
      end

      dep_list.each do |dependency|
        record_dep_package(
          name: dependency['name'],
          reference: "N/A for go.mod/go.sum dependencies",
          version_tag: dependency['version'],
          dependency_file: "go.mod",
          type: "go_mod"
        )
      end
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

    def get_name(line)
      dep_list = line.split(' ')
      dep_list[0]
    end

    def get_version(line)
      dep_list = line.split(' ')
      dep_list[1]
    end

    def should_run?
      @repository.dep_lock_present? ||
        @repository.go_mod_present? ||
        @repository.go_sum_present?
    end

    def record_dep_package(dependency_file:, name:, version_tag:, reference:, type:)
      report_dependency(
        dependency_file,
        type: type,
        name: name,
        reference: reference,
        version_tag: version_tag
      )
    end
  end
end
