require 'open3'
require 'salus/scan_report'
require 'salus/shell_result'

module Salus::Scanners
  # Super class for all scanner objects.
  class Base
    class UnhandledExitStatusError < StandardError; end
    class InvalidScannerInvocationError < StandardError; end

    attr_reader :report

    def initialize(repository:, config:)
      @repository = repository
      @config = config
      @report = Salus::ScanReport.new(
        name,
        custom_failure_message: @config['failure_message']
      )
    end

    def name
      self.class.name.sub('Salus::Scanners::', '')
    end

    # The scanning logic or something that calls a scanner.
    def run
      raise NoMethodError
    end

    # Returns TRUE if this scanner is appropriate for this repo, ELSE false.
    def should_run?
      raise NoMethodError
    end

    # Wraps the actual workhorse #run method with some boilerplate:
    # - appends the scan report to the given global salus report
    # - uses the #record method of @report to record the running time of the scan,
    #   and also to pass/fail the scan if #run failed to do so
    # - catches any exceptions, appending them to both the scan report's error
    #   collection and the global salus scan's error collection
    def run!(salus_report:, required:, pass_on_raise:, reraise:)
      salus_report.add_scan_report(@report, required: required)

      begin
        @report.record { run }

        if @report.errors.any?
          pass_on_raise ? @report.pass : @report.fail
        end
      rescue StandardError => e
        error_data = {
          message: "Unhandled exception running #{name}: #{e.class}: #{e}",
          error_class: e.class,
          backtrace: e.backtrace.take(5)
        }

        pass_on_raise ? @report.pass : @report.fail

        # Record the error so that the Salus report captures the issue.
        @report.error(error_data)
        salus_report.error(error_data)

        raise if reraise
      end
    end

    # Runs a command on the terminal.
    def run_shell(command, env: {}, stdin_data: '')
      # If we're passed a string, convert it to an array beofre passing to capture3
      command = command.split unless command.is_a?(Array)
      Salus::ShellResult.new(*Open3.capture3(env, *command, stdin_data: stdin_data))
    end

    # Add a textual logline to the report. This is for humans
    def log(string)
      @report.log(string)
    end

    # Tag the report as having completed successfully
    def report_success
      @report.pass
    end

    # Tag the report as having failed
    # (ie. a vulnerability was found, the scanner errored out, etc)
    def report_failure
      @report.fail
    end

    # Report information about this scan.
    def report_info(type, message)
      @report.info(type, message)
    end

    # Report a scanner warning such as a possible misconfiguration
    def report_warn(type, message)
      @report.warn(type, message)
    end

    # Report the STDOUT from the scanner.
    def report_stdout(stdout)
      @report.info(:stdout, stdout)
    end

    # Report the STDERR from the scanner.
    def report_stderr(stderr)
      @report.info(:stderr, stderr)
    end

    # Report an error in a scanner.
    def report_error(message, hsh = {})
      hsh[:message] = message
      @report.error(hsh)
    end

    # Report a dependency of the project
    def report_dependency(file, hsh = {})
      hsh = hsh.merge(dependency_file: file)
      @report.dependency(hsh)
    end
  end
end
