require 'active_support'
require 'active_support/core_ext'
require 'salus/bugsnag'
require 'salus/cli'
require 'salus/repo'
require 'salus/scanners'
require 'salus/config'
require 'salus/config_exception'
require 'salus/processor'
require 'salus/plugin_manager'
require 'sarif/sarif_report'
require 'cyclonedx/report'
require 'salus/report_request'

module Salus
  VERSION = '2.13.4'.freeze
  DEFAULT_REPO_PATH = './repo'.freeze # This is inside the docker container at /home/repo.

  SafeYAML::OPTIONS[:default_mode] = :safe

  EXIT_SUCCESS = 0
  EXIT_FAILURE = 1

  URI_DELIMITER = ' '.freeze # space

  class << self
    include SalusBugsnag

    def scan(
      config: nil,
      quiet: false,
      verbose: false,
      repo_path: DEFAULT_REPO_PATH,
      use_colors: true,
      filter_sarif: "",
      ignore_config_id: "",
      heartbeat: true
    )
      Salus::PluginManager.load_plugins

      Salus::PluginManager.send_event(:salus_scan, method(__method__).parameters)

      ### Heartbeat ###
      if !quiet && heartbeat
        heartbeat_thr = heartbeat(60) # Print a heartbeat every 60s. [0s, 60s, 120s, ...]
      end

      ### Configuration ###
      # Config option would be: --config="<uri x> <uri y> etc"
      configuration_directives = (ENV['SALUS_CONFIGURATION'] || config || '').split(URI_DELIMITER)

      processor = Salus::Processor.new(configuration_directives, repo_path: repo_path,
                                       filter_sarif: filter_sarif,
                                       ignore_config_id: ignore_config_id)

      ### Scan Project ###
      # Scan project with Salus client.
      processor.scan_project

      ### Reporting ###
      # Print report to stdout.
      puts processor.string_report(verbose: verbose, use_colors: use_colors) unless quiet

      # Try to send Salus reports to remote server or local files.
      processor.export_report

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
