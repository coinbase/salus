module Salus
  class YarnLock
    def initialize(file_path)
      @content = File.read(file_path)
      @dep_lines = {}
    end

    def add_line_number(vulns)
      parse_yarn_lock
      vulns.each do |vul|
        package = vul['Package']
        patched = vul['Patched in']
        if @dep_lines[package] && (patched.start_with?('>=') || patched == 'No patch available') &&
            ['<=', '==', '!='].all? { |op| !patched.include?(op) } &&
            @dep_lines[package].keys.all? { |k| Gem::Version.correct?(k) }
          min_version = @dep_lines[package].keys.map { |k| Gem::Version.new(k) }.min.to_s
          if !@dep_lines[package][min_version].to_s.nil?
            vul['Line number'] = @dep_lines[package][min_version]
          end
        end
      end
    end

    def parse_yarn_lock
      curr_dep_name = ""
      version_prefix = "  \"version\" \""

      # yarn.lock looks like
      # "abcd@^7.0.0":
      #    "version" "7.0.0"
      # ...
      # where "abcd@^7.0.0" and "version" could be with and without quotes

      @content.split("\n").each_with_index do |line, i|
        if line.start_with?("\"") && line.include?("@") # Ex. "yargs@1.2.3":
          at_index = if line.start_with?("\"@") # Ex. "@babel/abc@1.2.3":
                       line[2..].index("@") + 2
                     else
                       line.index("@")
                     end
          curr_dep_name = line[1..at_index - 1]
        elsif line.size.positive? && line[0].match(/\w/) && line.include?("@")
          # like above but no quotes, Ex yargs@1.2.3
          at_index = line.index("@")
          curr_dep_name = line[0..at_index - 1]
        elsif line.start_with?(version_prefix) && line.end_with?("\"")
          # Ex. "version" "1.2.3"
          version = line[13..-2]
          @dep_lines[curr_dep_name] = {} if @dep_lines[curr_dep_name].nil?
          @dep_lines[curr_dep_name][version] = i + 1
        elsif line.start_with?("  version \"") && line.end_with?("\"")
          # like above but w/o quotes
          version = line[11..-2]
          @dep_lines[curr_dep_name] = {} if @dep_lines[curr_dep_name].nil?
          @dep_lines[curr_dep_name][version] = i + 1
        end
      end
    end
  end
end
