require 'bugsnag'
require 'active_support'
require 'active_support/core_ext'

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
  VERSION = '2.8.1'.freeze
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
      repo_path: DEFAULT_REPO_PATH,
      use_colors: true,
      heartbeat: true
    )

      ### Heartbeat ###
      if !quiet && heartbeat
        heartbeat_thr = heartbeat(60) # Print a heartbeat every 60s. [0s, 60s, 120s, ...]
      end

      ### Configuration ###
      # Config option would be: --config="<uri x> <uri y> etc"
      configuration_directives = (ENV['SALUS_CONFIGURATION'] || config || '').split(URI_DELIMITER)
      processor = Salus::Processor.new(configuration_directives, repo_path: repo_path)

      ### Scan Project ###
      # Scan project with Salus client.
      processor.scan_project

      ### Reporting ###
      # Print report to stdout.
      puts processor.string_report(verbose: verbose, use_colors: use_colors) unless quiet

      # Try to send Salus reports to remote server or local files.
      begin
        processor.export_report
      rescue StandardError => e
        raise e if ENV['RUNNING_SALUS_TESTS']

        puts "Could not send Salus report: (#{e.class}: #{e.message})"
        Bugsnag.notify(e)
      end

      heartbeat_thr&.kill

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

    # This method spawns a thread in order to print a heartbeat
    def heartbeat(time)
      Thread.new do
        loop do
          puts "[INFORMATIONAL: #{Time.now}]: Salus is running."
          sleep time
        end
      end
    end
  end
end
