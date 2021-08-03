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
      goSumPath = "#{@repository.path_to_repo}/go.sum"
      depList = []

      File.open(goSumPath).each(sep="=\n") do |line|
        depList.append({"fullDependency" => line, "name" => getName(line), "version" => getVersion(line)})
      end

      depList.each do |dependency|
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
      goModPath = "#{@repository.path_to_repo}/go.mod"
      depList = []
      parseLine = false

      File.open(goModPath).each(sep="\n") do |line|
        if line.include? "require ("
          parseLine = true
        elsif line.include? ")"
          parseLine = false
        elsif parseLine
          depList.append({"fullDependency" => line, "name" => getName(line), "version" => getVersion(line)})
        end
      end

      depList.each do |dependency|
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

    def getName(line)
      depList = line.split(' ') 
      depList[0]
    end

    def getVersion(line)
      depList = line.split(' ')
      depList[1]
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
