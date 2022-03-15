module Salus
  class GoDependencyParser
    class SemVersion < Gem::Version; end
    attr_reader :go_dependencies
    def initialize(path)
      msg = "go.sum not found!"
      raise StandardError, msg unless File.exist?(path)

      @go_sum_content = File.read(path)
      @go_dependencies = {
        "parsed" => [],
        "skipped" => []
      }
    end

    def parse
      parse_dependencies
    end

    def select_dependencies(all_dependencies)
      dependencies = {}
      # Pick specific version of dependencies
      # If multiple versions of dependencies are found then pick the max version to mimic MVS
      # https://go.dev/ref/mod#minimal-version-selection
      all_dependencies["parsed"].each do |dependency|
        lib = dependency["namespace"] + "/" + dependency["name"]
        version = dependency["version"].to_s.gsub('v', '').gsub('+incompatible', '')
        if dependencies.key?(lib)
          dependencies[lib] = version if SemVersion.new(version) >
            SemVersion.new(dependencies[lib])
        else
          dependencies[lib] = version
        end
      end
      dependencies
    end

    private

    def parse_dependencies
      @go_sum_content.each_line do |line|
        # Split on space
        # github.com/google/go-cmp v0.5.3/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
        # Validate 3 parts - name, version and checksum
        parts = line.split
        if parts.length == 3
          names = parts[0].split("/")
          @go_dependencies["parsed"].append(
            {
              "namespace" => names[0..-2].join("/").to_s,
              "name" => names[-1].to_s,
              "version" => parts[1].to_s.gsub('/go.mod', ''),
              "checksum" => parts[2].to_s.gsub('h1:', '')
            }
          )
        else
          @go_dependencies["skipped"].append(line)
        end
      end
    end
  end
end
