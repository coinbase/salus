require 'json'
require 'yaml'
require 'cocoapods'

module Salus
  class PodlockDependencyParser
    attr_reader :podlock_dependencies
    def initialize(path)
      begin
        podfile_lock = YAML.safe_load(File.read(path), [Symbol])
      rescue StandardError
        raise 'Unable to parse Podfile.lock file'
      end

      begin
        lockfile = Pod::Lockfile.new(podfile_lock)
      rescue StandardError
        raise 'Unable to initialize Pod::Lockfile from YAML hash'
      end

      @podfile_content = (lockfile.send :pod_versions)
      @podlock_dependencies = []
    end

    def parse
      @podfile_content.each do |dependency_entry|
        @podlock_dependencies.append(
          {
            "pod" => dependency_entry[0],
              "version" => dependency_entry[1].to_s
          }
        )
      end
    end
  end
end
