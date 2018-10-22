require 'json'

module Salus
  class ScanReport
    attr_reader :scanner_name, :logs, :info, :errors, :running_time

    def initialize(scanner_name)
      @scanner_name = scanner_name

      @passed = nil
      @running_time = nil
      @logs = []
      @info = {}
      @errors = []
    end

    def record
      started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      yield
      @passed = true if @passed.nil?
      @running_time = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at).round(2)
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

    def log(string, verbose: false, color: nil, newline: true)
      string += "\n" if newline
      @logs << [string, verbose, color]
    end

    def info(type, value)
      @info[type] ||= []
      @info[type] << value
    end

    def to_h
      {
        passed: @passed,
        running_time: running_time,
        info: (@info.empty? ? nil : @info)
      }.compact
    end
  end
end
