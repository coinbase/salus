require 'json'

module Salus
  class ScanReport
    attr_reader :scanner_name, :running_time

    def initialize(scanner_name)
      @scanner_name = scanner_name
      @passed = nil
      @running_time = nil
      @info = {}
      @errors = []
    end

    def record
      started_at = monotime

      yield

      # If the block failed to pass/fail the scan,
      # default to pass if no errors were recorded
      @passed = @errors.empty? if @passed.nil?
    ensure
      @running_time = (monotime - started_at).round(2)
    end

    def pass
      @passed = true
    end

    def fail
      @passed = false
    end

    def passed?
      @passed == true
    end

    def failed?
      @passed == false
    end

    def info(type, value)
      @info[type] = value
    end

    def error(hsh)
      @errors << hsh
    end

    def dependency(hsh)
      @info[:dependencies] ||= []
      @info[:dependencies] << hsh
    end

    def to_h
      {
        scanner_name: scanner_name,
        passed: passed?,
        running_time: @running_time,
        info: @info,
        errors: @errors
      }
    end

    def to_s(verbose:, wrap:)
      banner = render_banner

      # If the scan succeeded and verbose is false, just output the banner
      # indicating pass/fail
      return banner if @passed && !verbose

      # Because we need to wrap indented paragraphs, correct the wrap
      # by the indentation level
      wrap = (wrap.nil? ? nil : wrap - 2)

      output = banner

      if !@info.empty? && verbose
        stringified_info = indent(wrapify(JSON.pretty_generate(@info), wrap))
        output += "\n\n ~~ Metadata:\n\n#{stringified_info}".chomp
      end

      if !@errors.empty?
        stringified_errors = indent(wrapify(JSON.pretty_generate(@errors), wrap))
        output += "\n\n ~~ Errors:\n\n#{stringified_errors}".chomp
      end

      output
    end

    private

    def render_banner
      banner = "==== #{@scanner_name}: #{@passed ? 'PASSED' : 'FAILED'}"
      banner += " in #{@running_time}s" if @running_time
      banner
    end

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
      text.each_line("\n").map { |line| line == "\n" ? "\n" : ('  ' + line) }.join
    end

    def monotime
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
