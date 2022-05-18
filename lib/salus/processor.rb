require 'uri'
require 'salus/report'
require 'salus/plugin_manager'
require 'salus/repo_searcher'

module Salus
  class Processor
    class InvalidConfigSourceError < StandardError; end

    include Salus::SalusBugsnag

    attr_reader :config, :report

    # If configuration sources are not provided, we'll automatically scan the
    # repo root for a configuration file with this default name
    DEFAULT_CONFIG_SOURCE = "file:///salus.yaml".freeze

    def initialize(configuration_sources = [], repo_path: DEFAULT_REPO_PATH, filter_sarif: "",
                   ignore_config_id: "", cli_scanners_to_run: [],
                   report_filter: DEFAULT_REPORT_FILTER)
      @repo_path = File.expand_path(repo_path)
      @filter_sarif = filter_sarif
      ignore_ids = ignore_config_id.split(',').map(&:strip)

      # Add default file path to the configs if empty.
      configuration_sources << DEFAULT_CONFIG_SOURCE if configuration_sources.empty?
      valid_sources = []
      source_data = []

      # Import each config file in order.
      configuration_sources.each do |source|
        body = fetch_config_file(source, repo_path)
        if !body.nil?
          source_data << body
          valid_sources << source
        else
          puts "\n\nFailed to load #{source}\n\n"
        end
      end

      @config = Salus::Config.new(source_data, ignore_ids)
      @config.active_scanners = Set.new(cli_scanners_to_run) if !cli_scanners_to_run.empty?

      report_uris = get_report_uris(report_filter)

      sources = {
        sources: {
          configured: configuration_sources,
          valid: valid_sources
        }
      }

      @report = Report.new(
        report_uris: report_uris,
        builds: @config.builds,
        project_name: @config.project_name,
        custom_info: @config.custom_info,
        config: @config.to_h.merge(sources),
        repo_path: repo_path,
        filter_sarif: filter_sarif,
        ignore_config_id: ignore_config_id,
        report_filter: report_filter
      )
    end

    def fetch_config_file(source_uri, repo_path)
      uri = URI(source_uri)

      content = case uri.scheme
                when Salus::Config::LOCAL_FILE_SCHEME_REGEX
                  location = "#{repo_path}/#{uri.host}#{uri.path}"
                  File.read(location) if Dir[location].any?
                when Salus::Config::REMOTE_URI_SCHEME_REGEX
                  Faraday.get(source_uri).body
                else
                  raise InvalidConfigSourceError, 'Unknown config file source.'
                end

      begin
        if !content.nil? && !YAML.safe_load(content).is_a?(Hash)
          msg = "config source #{source_uri} content cannot be parsed as Hash. "\
              "Content: #{content.inspect}"
          bugsnag_notify(msg)
          content = nil
        end
      rescue Psych::SyntaxError
        msg = "Salus config format is invalid yaml. "\
              "You may check salus.yaml file for formatting issue."
        puts "** Error **: #{msg}"
        bugsnag_notify(msg)
        exit(EXIT_FAILURE)
      end

      content
    end

    def run_scanner(config, scanner_class, scanner_name)
      threads = []
      files_copied = []
      reraise_exceptions = ENV.key?('RUNNING_SALUS_TESTS')

      # We won't auto cleanup - we'll manually delete any copied fields after
      # the various threads have finished
      copied = RepoSearcher.new(@repo_path, config, false).matching_repos do |repo|
        threads << Thread.new do
          scanner = scanner_class.new(repository: repo, config: config)

          unless scanner.should_run?
            Salus::PluginManager.send_event(:skip_scanner, scanner_name)
            next
          end

          # Protect the append as each thread will be appending to our scanners_ran array
          puts "#{scanner_name} is scanning..."
          @mutex.synchronize { @scanners_ran << scanner }

          Salus::PluginManager.send_event(:run_scanner, scanner_name)

          scanner.run!(
            salus_report: @report, # Salus::Report
            required: @config.enforced_scanners.include?(scanner_name),
            pass_on_raise: @config.scanner_configs[scanner_name]['pass_on_raise'],
            reraise: reraise_exceptions
          )
          puts "#{scanner_name} has finished"
        end
      end
      files_copied.concat(copied) unless copied.empty?
      [threads, files_copied]
    end

    def scan_project
      # Record overall running time of the scan
      threads = []
      files_copied = []
      @scanners_ran = []
      @mutex = Mutex.new

      @report.record do
        # If we're running tests, re-raise any exceptions raised by a scanner
        # (vs. just catching them and recording them in a real run)

        Config::SCANNERS.each do |scanner_name, scanner_class|
          config = @config.scanner_configs.fetch(scanner_name, {})

          unless @config.scanner_active?(scanner_name)
            Salus::PluginManager.send_event(:skip_scanner, scanner_name)
            next
          end

          scanner_threads, copied = run_scanner(config, scanner_class, scanner_name)

          threads.concat(scanner_threads)
          files_copied.concat(copied)
        end

        threads.each(&:join)
        cleanup(files_copied.uniq)

        Salus::PluginManager.send_event(:scanners_ran, @scanners_ran, @report)
      end
    end

    def cleanup(files)
      # Our threads have finished so we can go an cleanup any files we copied
      files.each do |file|
        File.delete(file)
      end
    end

    def create_full_sarif_diff(sarif_diff_full, git_diff)
      sarif_file_new = sarif_diff_full[0]
      sarif_file_old = sarif_diff_full[1]
      info = "\nCreating full sarif diff report from #{sarif_file_new} and #{sarif_file_old}"
      info += " with git diff #{git_diff}" if git_diff != ''
      puts info

      [sarif_file_new, sarif_file_old].each do |f|
        raise Exception, "sarif diff file name is empty #{f}" if f.nil? || f == ""
      end

      sarif_file_new = File.join(@repo_path, sarif_file_new)
      sarif_file_old = File.join(@repo_path, sarif_file_old)
      git_diff = File.join(@repo_path, git_diff) if git_diff != ''

      files = [sarif_file_new, sarif_file_old]
      files.push git_diff if git_diff != ''
      files.each do |f|
        if !Salus::Report.new(repo_path: @repo_path).safe_local_report_path?(f)
          raise Exception, "sarif/git diff file path should not be outside working dir #{f}"
        end
      end

      sarif_new = JSON.parse(File.read(sarif_file_new))
      sarif_old = JSON.parse(File.read(sarif_file_old))
      git_diff = File.read(git_diff) if git_diff != ''
      filtered_full_sarif = Sarif::BaseSarif.report_diff(sarif_new, sarif_old, git_diff)

      @report.full_diff_sarif = filtered_full_sarif
    end

    # Returns an ASCII version of the report.
    def string_report(verbose: false, use_colors: false)
      @report.to_s(verbose: verbose, use_colors: use_colors)
    end

    # Sends to the report to configured report URIs.
    def export_report
      @report.export_report
    end

    # Returns true is the scan succeeded.
    def passed?
      @report.passed?
    end

    private

    # If report_filter is none, Returns an empty array for reporting endpoints
    # Else it resolves URIs and returns
    def get_report_uris(report_filter)
      return [] if report_filter == NONE_REPORT_FILTER

      interpolate_local_report_uris(@config.report_uris)
    end

    # If the URI is local, we will need to prepend the repo_path since
    # the report URI is relative to the root of the repo. This allows us
    # to print reports to a location outside of Salus's docker container.
    def interpolate_local_report_uris(report_directives)
      report_directives.map do |report_uri|
        uri_object = URI(report_uri['uri'])
        scheme = URI(report_uri['uri']).scheme
        file_path = "#{uri_object.host}#{uri_object.path}"

        if Salus::Config::LOCAL_FILE_SCHEME_REGEX.match?(scheme)
          report_uri['uri'] = "file://#{File.join(@repo_path, file_path)}"
        end

        report_uri
      end
    end
  end
end
