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
      end
    end

    def record_dep_from_go_sum
      go_sum_path = "#{@repository.path_to_repo}/go.sum"
      dep_list = []

      File.foreach(go_sum_path).each("=\n") do |line|
        line = line.strip
        next if line.empty?

        go_sum_regex = %r{(?<namespace>(.*)(?!/go\.mod))/(?<name>[^\s]*)
        (\s)*(?<version>(.*))(\s)*h1:(?<checksum>(.*))}x

        if (matches = line.match(go_sum_regex))
          dep_list.append(
            {
              "namespace" => (matches[:namespace]).to_s,
              "name" => (matches[:name]).to_s,
              "version" => (matches[:version]).to_s.gsub(%r{/go.mod}, '').strip,
              "checksum" => (matches[:checksum]).to_s
            }
          )
        end
      end
      # Note references are hashes meant for packages in Gopkg.lock files
      dep_list.each do |dependency|
        record_dep_package(
          namespace: dependency["namespace"],
          name: dependency["name"],
          reference: "N/A for go.mod/go.sum dependencies",
          version_tag: dependency['version'],
          dependency_file: "go.sum",
          checksum: dependency['checksum'],
          type: "golang"
        )
      end
    end

    def record_dep_from_go_mod
      # Typically go.mod files don't contain all of the transitive deps/info
      # a go.sum file would. Instead of parsing go.mod files, warn that
      # go.sum is missing and send an event
      message = "WARNING: No go.sum/Gopkg.lock found. "\
      "Currently go.mod is unsupported for reporting Golang dependencies."
      report_warn(:report_go_dep_missing_go_sum, message)
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
          type: "golang",
          namespace: "",
          checksum: ""
        )
      end
    end

    def self.supported_languages
      ['go']
    end

    def should_run?
      @repository.dep_lock_present? ||
        @repository.go_mod_present? ||
        @repository.go_sum_present?
    end

    def record_dep_package(
      dependency_file:,
      name:,
      version_tag:,
      reference:,
      type:,
      namespace:,
      checksum:
    )

      report_dependency(
        dependency_file,
        type: type,
        namespace: namespace,
        name: name,
        reference: reference,
        version_tag: version_tag,
        checksum: checksum
      )
    end
  end
end
