module Salus
  class PackageLockJson
    attr_reader :deps
    def initialize(file_path)
      @content = File.read(file_path)
      @deps = {}
    end

    def add_line_number(json)
      record_dep_locations

      json[:advisories].each do |_id, vul_info|
        dep_name = vul_info[:module_name]
        if vul_info[:findings].all? { |v| Gem::Version.correct?(v[:version]) }
          vul_version = vul_info[:findings].map { |v| Gem::Version.new(v[:version]) }.min.to_s
          if !@deps.dig(dep_name, vul_version).to_s.nil?
            vul_info[:line_number] = @deps[dep_name][vul_version]
          end
        end
      end
    end

    # Store line numbers of dependencies in @dep. Ex
    # { "dep_name " =>
    #    { "1.0.0" => 10   # version 1.0.0 => line 10
    #      "2.0.0" => 20   # version 2.0.0 => line 20
    #    }
    # }
    def record_dep_locations
      data = JSON.parse(@content)
      get_dep_names(data)
      curr_line = 0
      lines = @content.split("\n")
      lines.each do |line|
        line.strip!
        # if line with dependency name, like
        #   "math-random": {
        start_chars = "\": {"
        if line.end_with?(start_chars) && line.start_with?("\"")
          quote_index2 = line[1..].index(start_chars)
          dep_name = line[1..quote_index2]
          # right now version is always one line below the dependency name, like
          #    "math-random": {
          #      "version": "1.2.3",
          if @deps[dep_name] && lines[curr_line + 1]
            next_line = lines[curr_line + 1].strip
            if next_line.start_with?("\"version\": \"") && next_line.end_with?("\",")
              version = next_line[12..-3].strip
              @deps[dep_name][version] = curr_line + 2
            end
          end
        end
        curr_line += 1
      end
    end

    # recursively store all dependency names as keys
    def get_dep_names(data)
      return unless data.key?("dependencies")

      data['dependencies'].each do |name, dep_info|
        @deps[name] = {}
        get_dep_names(dep_info) if dep_info['dependencies']
      end
    end
  end
end
