require 'json'
require 'salus/formatting'

module Salus
  class ScanReport
    include Formatting

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

    def to_s(verbose:, wrap:, use_colors:)
      banner = render_banner(use_colors: use_colors)

      # If the scan succeeded and verbose is false, just output the banner
      # indicating pass/fail
      return banner if @passed && !verbose

      # Because we need to wrap indented paragraphs, correct the wrap
      # by the indentation level
      indented_wrap = (wrap.nil? ? nil : wrap - INDENT_SIZE)

      output = banner

      if !@info.empty? && verbose
        stringified_info = indent(wrapify(JSON.pretty_generate(@info), indented_wrap))
        output += "\n\n ~~ Metadata:\n\n#{stringified_info}".chomp
      end

      if !@errors.empty?
        stringified_errors = indent(wrapify(JSON.pretty_generate(@errors), indented_wrap))
        output += "\n\n ~~ Errors:\n\n#{stringified_errors}".chomp
      end

      output
    end

    private

    def render_banner(use_colors:)
      status = passed? ? 'PASSED' : 'FAILED'
      status = colorize(status, (passed? ? :green : :red)) if use_colors

      banner = "==== #{@scanner_name}: #{status}"
      banner += " in #{@running_time}s" if @running_time

      banner
    end

    def monotime
      # Measure elapsed time with a monotonic clock in order to be resilient
      # to changes in server time
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
