require 'bugsnag'

if ENV['BUGSNAG_API_KEY']
  Bugsnag.configure do |config|
    config.endpoint = ENV.fetch('BUGSNAG_ENDPOINT', 'notify.bugsnag.com')
    config.api_key = ENV['BUGSNAG_API_KEY']
  end
end

# Hook at_exit to send off the fatal exception if it occurred
at_exit { Bugsnag.notify($ERROR_INFO) if $ERROR_INFO }

require 'salus/cli'
require 'salus/repo'
require 'salus/scanners'
require 'salus/config'
require 'salus/processor'

module Salus
  VERSION = '1.0.0'.freeze
  DEFAULT_REPO_PATH = './repo'.freeze # This is inside the docker container at /home/repo.

  SafeYAML::OPTIONS[:default_mode] = :safe

  EXIT_SUCCESS = 0
  EXIT_FAILURE = 1

  URI_DELIMITER = ' '.freeze # space

  class << self
    def scan(
      config: nil,
      quiet: false,
      verbose: false,
      output_stream: STDOUT,
      repo_path: DEFAULT_REPO_PATH
    )
      ### Configuration ###
      # Config option would be: --config="<uri x> <uri y> etc"
      configuration_directives = (ENV['SALUS_CONFIGURATION'] || config || '').split(URI_DELIMITER)
      processor = Salus::Processor.new(configuration_directives, repo_path: repo_path)

      ### Scan Project ###
      # Scan project with Salus client.
      processor.scan_project

      ### Reporting ###
      # Print report to the given stream (STDOUT by default)
      output_stream.puts(processor.string_report(verbose: verbose)) unless quiet

      # Try to send Salus reports to remote server or local files.
      begin
        processor.export_report
      rescue StandardError => e
        raise e if ENV['RUNNING_SALUS_TESTS']
        puts "Could not send Salus report: (#{e.class}: #{e.message})"
      end

      # System exit with success or failure - useful for CI builds.
      system_exit(processor.passed? ? EXIT_SUCCESS : EXIT_FAILURE)
    end

    private

    # This method is mapped directly to exit() to make testing easier
    # since we can stub it. Otherwise our test process would actually
    # just exit early.
    def system_exit(status)
      exit(status)
    end
  end
end
