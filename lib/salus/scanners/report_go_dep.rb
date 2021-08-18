require 'toml'
require 'salus/scanners/base'
require 'salus/plugin_manager'
require 'salus/report'

# Report the use of Go packages captured in one of Gopkg.lock/go.sum/go.mod files.
# https://github.com/golang/dep

module Salus::Scanners
  class ReportGoDep < Base
    def run
      unless should_run? 
      end
      if @repository.go_sum_present?
        record_dep_from_go_sum
      elsif @repository.dep_lock_present?
        record_dep_from_go_lock_package
      elsif @repository.go_mod_present?
        record_dep_from_go_mod
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

      File.foreach(go_sum_path).each("=\n") do |line|
        line = line.strip
        next if line.empty?

        line_info = get_line_info(line)

        dep_list.append(
          {
            "fullDependency" => line,
            "name" => line_info[0],
            "version" => line_info[1]
          }
        )
      end
      # Note references are hashes meant for packages in Gopkg.lock files
      dep_list.each do |dependency|
        record_dep_package(
          name: dependency['name'],
          reference: "N/A for go.mod/go.sum dependencies",
          version_tag: dependency['version'],
          dependency_file: "go.sum",
          type: "golang"
        )
      end
    end

    def record_dep_from_go_mod
      # Typically go.mod files don't contain all of the transitive deps/info
      # a go.sum file would. Instead of parsing go.mod files, warn that
      # go.sum is missing and send an event
      warning_string = "WARNING: No go.sum/Gopkg.lock found. "\
      "Currently go.mod is unsupported for reporting Golang dependencies."
      report_warn(:report_go_dep_missing_go_sum, warning_string)

      data = "This repository contains no go.sum or Gopkg.lock file. Currently "\
      "go.mod files are unsupported for reporting Golang dependencies"
      Salus::PluginManager.send_event(:report_go_dep_scan, data)
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
          type: "golang"
        )
      end
    end

    def self.supported_languages
      ['go']
    end

    def get_line_info(line)
      dep_list = line.split(' ')
      dep_list
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
