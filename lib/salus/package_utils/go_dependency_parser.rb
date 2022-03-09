module Salus
  class GoDependencyParser
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
