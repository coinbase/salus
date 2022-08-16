module Salus
  class YarnLockfileFormatter
    def initialize(file)
      @content = file
    end

    def format
      yaml_obj = convert_to_yaml
      lockfile_content = parse_yaml_obj(yaml_obj)
      split_lockfile(lockfile_content)
    end

    private

    attr_reader :content

    def convert_to_yaml
      data = lambda do |line|
        return line unless line.match?(/^[\w"]/)

        "\"#{line.gsub(/\"|:\n$/, '')}\":\n"
      end
      add_colon = ->(l) { l.sub(/(?<=\w|")\s(?=\w|")/, ": ") }

      content.lines.map(&data).map(&add_colon).join
    end

    def parse_yaml_obj(yaml)
      YAML.safe_load(yaml)
    rescue StandardError
      report_error(
        "An error occurred while formatting yarn.lock for auto-fixing: #{e}, #{e.backtrace}"
      )
    end

    def split_lockfile(lockfile_content)
      lockfile_content.to_a.each_with_object({}) do |(names, value), result|
        names.split(", ").each { |name| result[name] = value }
      end
    end
  end
end
