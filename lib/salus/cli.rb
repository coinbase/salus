require 'thor'

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
    class_option :ignore_config_id,
                 desc: 'Ignore id in salus config.',
                 type: :string,
                 default: ''

    desc 'scan', 'Scan the source code of a repository.'
    def scan
      Salus.scan(
        config: options[:config],
        quiet: options[:quiet],
        verbose: options[:verbose],
        repo_path: options[:repo_path],
        use_colors: !options[:no_colors],
        filter_sarif: options[:filter_sarif],
        ignore_config_id: options[:ignore_config_id]
      )
    end
  end
end
