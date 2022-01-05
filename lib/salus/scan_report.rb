require 'json'
require 'salus/formatting'
module Salus
  class ScanReport
    include Formatting

    attr_reader :scanner_name, :running_time, :errors, :version, :repository,
                :custom_failure_message

    def initialize(scanner_name, custom_failure_message: nil, repository: nil)
      @scanner_name = scanner_name
      @passed = nil
      @running_time = nil
      @logs = nil
      @info = {}
      @warn = {}
      @errors = []
      @custom_failure_message = custom_failure_message
      @repository = repository # Salus::Repo used to track what this scan report
      # is being ran against.  Needed for recusive scanning
    end

    def add_version(scanner_version)
      @version = scanner_version
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

    def log(string)
      @logs ||= ''
      @logs += "#{string}\n"
    end

    def info(type, value)
      @info[type] = value
    end

    def warn(type, value)
      @warn[type] = value
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
        version: @version,
        passed: passed?,
        running_time: @running_time,
        logs: @logs&.chomp,
        warn: @warn,
        info: @info,
        errors: @errors
      }.compact
    end

    def to_s(verbose:, wrap:, use_colors:)
      banner = render_banner(use_colors: use_colors)

      # If the scan succeeded, verbose is false, and there are no warnings, just output the banner
      # indicating pass/fail
      return banner if @passed && !verbose && @warn.empty?

      # Because we need to wrap indented paragraphs, correct the wrap
      # by the indentation level
      indented_wrap = (wrap.nil? ? nil : wrap - INDENT_SIZE)

      output = banner

      if !@warn.empty?
        stringified_warnings = indent(wrapify(JSON.pretty_generate(@warn), indented_wrap))
        output += "\n\n ~~ Scanner Warnings:\n\n#{stringified_warnings}".chomp
      end

      # If the scan succeeded, verbose is false, just output the pass/fail banner and warnings
      return output if @passed && !verbose

      if !@logs.nil?
        logs = indent(wrapify(@logs, indented_wrap))
        output += "\n\n ~~ Scanner Logs:\n\n#{logs.chomp}"
      end

      if !@info.empty? && verbose
        stringified_info = indent(wrapify(JSON.pretty_generate(@info), indented_wrap))
        output += "\n\n ~~ Metadata:\n\n#{stringified_info}".chomp
      end

      if !@errors.empty?
        stringified_errors = indent(wrapify(JSON.pretty_generate(@errors), indented_wrap))
        output += "\n\n ~~ Errors:\n\n#{stringified_errors}".chomp
      end

      if !@custom_failure_message.blank? && !passed?
        failure_message = indent(wrapify(@custom_failure_message, indented_wrap))
        output += "\n\n#{failure_message}".chomp
      end

      output
    end

    ##
    # Merge! will combine results from another scan report from the same scanner.
    # Run times are summed.  Logs and errors are appedned.  Warn/info hashes are merged.
    # Passed is logically ANDed.  If the scan_report passed to the method has a
    # custom_failure_method that one is adopted.
    #
    # @param [Salus::ScanReport] scan_report The scan report to merge into self
    # @returns [Salus::ScanReport]
    def merge!(scan_report)
      h = scan_report.to_h

      if @scanner_name != scan_report.scanner_name
        raise 'Unable to merge scan reports from different scanners'
      end

      if !@running_time.nil? || !scan_report.running_time.nil?
        @running_time ||= 0
        @running_time += scan_report.running_time || 0
      end

      if !@logs.nil? || h.key?(:logs)
        @logs ||= ""
        @logs += h[:logs]&.to_s
      end

      @passed &= scan_report.passed?
      @warn.merge!(h[:warn]) if !@warn.empty? || !h[:warn].empty?
      @info.merge!(h[:info]) if !@info.empty? || !h[:info].empty?
      @errors += h[:errors]

      if !scan_report.custom_failure_message.nil?
        @custom_failure_message = scan_report.custom_failure_message
      end
      self
    end

    private

    def render_banner(use_colors:)
      status = passed? ? 'PASSED' : 'FAILED'
      status = colorize(status, (passed? ? :green : :red)) if use_colors

      version_str = !@version.present? ? "" : " v#{@version}"
      banner = "==== #{@scanner_name}#{version_str}: #{status}"
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
