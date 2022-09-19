require 'active_support'
require 'active_support/core_ext'
require 'salus/bugsnag'
require 'salus/cli'
require 'salus/repo'
require 'salus/package_utils'
require 'salus/scanners'
require 'salus/config'
require 'salus/config_exception'
require 'salus/processor'
require 'salus/plugin_manager'
require 'sarif/sarif_report'
require 'cyclonedx/report'
require 'salus/report_request'
require 'salus/repo_searcher'
require 'salus/path_validator'
require 'salus/scanner_types'

module Salus
  VERSION = '2.21.3'.freeze
  DEFAULT_REPO_PATH = './repo'.freeze # This is inside the docker container at /home/repo.
  DEFAULT_REPORT_FILTER = 'all'.freeze
  NONE_REPORT_FILTER = 'none'.freeze

  SafeYAML::OPTIONS[:default_mode] = :safe

  EXIT_SUCCESS = 0
  EXIT_FAILURE = 1
  # report_error(:hard_error => true) will cause EXIT_HARD_ERROR
  # meaning salus will always fail even if pass_on_raise=true
  EXIT_HARD_ERROR = 2

  FULL_SARIF_DIFF_FORMAT = 'sarif_diff_full'.freeze

  URI_DELIMITER = ' '.freeze # space

  class << self
    include SalusBugsnag

    attr_accessor :hard_error_encountered

    # rubocop:disable Metrics/ParameterLists
    def scan(
      config: nil,
      quiet: false,
      verbose: false,
      repo_path: DEFAULT_REPO_PATH,
      use_colors: true,
      filter_sarif: "",
      sarif_diff_full: "",
      git_diff: "",
      ignore_config_id: "",
      only: [],
      reports: DEFAULT_REPORT_FILTER,
      heartbeat: true
    )
      # rubocop:enable Metrics/ParameterLists
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
                                       ignore_config_id: ignore_config_id,
                                       cli_scanners_to_run: only, report_filter: reports)

      unless sarif_diff_full.empty?
        return process_sarif_full_diff(processor, sarif_diff_full, git_diff)
      end

      ### Scan Project ###
      # Scan project with Salus client.
      processor.scan_project

      ### Reporting ###
      # Print report to stdout.
      puts processor.string_report(verbose: verbose, use_colors: use_colors) unless quiet

      processor.report.report_uris.reject! { |u| u['format'] == FULL_SARIF_DIFF_FORMAT }
      # Try to send Salus reports to remote server or local files.
      processor.export_report

      heartbeat_thr&.kill

      # System exit with success or failure - useful for CI builds.
      exit_status = if Salus.hard_error_encountered
                      EXIT_HARD_ERROR
                    else
                      processor.passed? ? EXIT_SUCCESS : EXIT_FAILURE
                    end
      system_exit(exit_status)
    end

    def process_sarif_full_diff(processor, sarif_diff_full, git_diff)
      begin
        processor.create_full_sarif_diff(sarif_diff_full, git_diff)
      rescue StandardError => e
        puts "Failed to get sarif diff #{e.inspect}"
        system_exit(EXIT_FAILURE)
      end

      processor.report.report_uris.select! { |u| u['format'] == FULL_SARIF_DIFF_FORMAT }
      processor.export_report

      if Sarif::BaseSarif.salus_passed?(processor.report.full_diff_sarif)
        system_exit(EXIT_SUCCESS)
      else
        puts "- Sarif diff contains vulnerabilities"
        system_exit(EXIT_FAILURE)
      end
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

Salus.hard_error_encountered = false
