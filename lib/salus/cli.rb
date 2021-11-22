require 'thor'
require 'salus/plugin_manager'

module Salus
  class CLI < Thor
    class_option :config,
                 aliases: ['-c'],
                 desc: 'Point to local or remote configuration files. '\
                       'e.g. --config="file://path/to/salus.yaml"',
                 type: :string,
                 default: ''
    class_option :quiet,
                 aliases: ['-q'],
                 desc: 'Do not print reports to STDOUT.',
                 type: :boolean,
                 default: false
    class_option :verbose,
                 aliases: ['-v'],
                 desc: 'Include "info" level data in reports printed to STDOUT.',
                 type: :boolean,
                 default: false
    class_option :repo_path,
                 aliases: ['-d'],
                 desc: 'Path to a directory to scan.',
                 type: :string,
                 default: './repo'
    class_option :no_colors,
                 desc: 'Do not colorize output.',
                 type: :boolean,
                 default: false
    class_option :filter_sarif,
                 desc: 'Path to sarif file. Filters out results from the sarif file.',
                 type: :string,
                 default: ''
    class_option :sarif_diff_full,
                 desc: 'Paths to sarif files separated by space. ' \
                       'Ex. (ex. "sarif_1.json sarif_2.json"). ' \
                       'Filters out results of sarif_2.json from sarif_1.json.',
                 type: :array,
                 default: []
    class_option :git_diff,
                 desc: 'Path to a git diff txt file. ' \
                       'Filter out --sarif-diff-full results that are most likely ' \
                       'not included in git diff.' \
                       'Can only be used with --sarif-diff-full. ',
                 type: :string,
                 default: ''
    class_option :ignore_config_id,
                 desc: 'Ignore id in salus config.',
                 type: :string,
                 default: ''
    class_option :only,
                 aliases: ['-o'],
                 desc: 'Activate certain scanners (overrides configured active scanners)',
                 type: :array,
                 default: []
    class_option :reports,
                 aliases: ['-r'],
                 desc: 'Filter the types of reports that will be executed',
                 type: :string,
                 default: 'all'

    desc 'scan', 'Scan the source code of a repository.'
    def scan
      Salus::PluginManager.send_event(:cli_scan, options)

      Salus.scan(
        config: options[:config],
        quiet: options[:quiet],
        verbose: options[:verbose],
        repo_path: options[:repo_path],
        use_colors: !options[:no_colors],
        filter_sarif: options[:filter_sarif],
        sarif_diff_full: options[:sarif_diff_full],
        git_diff: options[:git_diff],
        ignore_config_id: options[:ignore_config_id],
        only: options[:only],
        reports: options[:reports]
      )
    end

    def self.exit_on_failure?
      true
    end
  end
end
