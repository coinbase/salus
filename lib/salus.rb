require 'active_support'
require 'active_support/core_ext'
require 'salus/bugsnag'
require 'salus/cli'
require 'salus/repo'
require 'salus/scanners'
require 'salus/config'
require 'salus/processor'
require 'sarif/sarif_report'

module Salus
  VERSION = '2.10.18'.freeze
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
      heartbeat: true
    )

      ### Heartbeat ###
      if !quiet && heartbeat
        heartbeat_thr = heartbeat(60) # Print a heartbeat every 60s. [0s, 60s, 120s, ...]
      end

      ### Configuration ###
      # Config option would be: --config="<uri x> <uri y> etc"
      configuration_directives = (ENV['SALUS_CONFIGURATION'] || config || '').split(URI_DELIMITER)
      processor = Salus::Processor.new(configuration_directives, repo_path: repo_path,
                                       filter_sarif: filter_sarif)

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
        e = "Could not send Salus report. Exception: #{e}, Build info: #{processor.report.builds}"
        bugsnag_notify(e)
      end

      # if config writes sarif and --filter_sarif used
      if processor.report.sarif_report_path && !filter_sarif.empty?
        curr_sarif_file = processor.report.sarif_report_path
        filter_sarif_file = File.join(repo_path, filter_sarif)
        sarif_diff = filter_sarif_results(curr_sarif_file, filter_sarif_file)
        diff_file_txt = File.open(File.join(repo_path, 'salus_sarif_diff.txt'), 'w')
        sarif_diff.each do |d|
          diff_file_txt.write(JSON.pretty_generate(d) + "\n")
        end
        diff_file_txt.close
      end

      heartbeat_thr&.kill
      # System exit with success or failure - useful for CI builds.
      system_exit(processor.passed? ? EXIT_SUCCESS : EXIT_FAILURE)
    end

    def filter_sarif_results(curr_sarif_file, filter_sarif_file)
      curr_sarif_data, filter_sarif_data = [curr_sarif_file, filter_sarif_file].map do |f|
        JSON.parse(File.read(f))
      end
      curr_sarif_results = get_sarif_results(curr_sarif_data)
      filter_sarif_results = get_sarif_results(filter_sarif_data)
      curr_sarif_results - filter_sarif_results
    end

    def get_sarif_results(sarif_data)
      sarif_results = Set.new
      sarif_data["runs"].each do |run|
        scanner_name = run['tool']['driver']['name']
        run["results"].each do |result|
          # delete ruleIndex because the vulnerabilities of two scans may be
          # same but ordered differently
          result.delete('ruleIndex')
          result['scanner_name'] = scanner_name
          sarif_results.add(result)
        end
      end
      sarif_results
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
