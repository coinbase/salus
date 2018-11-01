module Salus
  module Formatting
    INDENT_SIZE = 2
    INDENT_STRING = (' ' * INDENT_SIZE).freeze

    def wrapify(string, wrap)
      return string if wrap.nil?

      parts = []

      string.each_line("\n").each do |line|
        if line == "\n"
          parts << "\n"
          next
        end

        line = line.chomp
        index = 0

        while index < line.length
          parts << line.slice(index, wrap) + "\n"
          index += wrap
        end
      end

      parts.join
    end

    def indent(text)
      # each_line("\n") rather than split("\n") because the latter
      # discards trailing empty lines. Also, don't indent empty lines
      text.each_line("\n").map { |line| line == "\n" ? "\n" : (INDENT_STRING + line) }.join
    end
  end
end
