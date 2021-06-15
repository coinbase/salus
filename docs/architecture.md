# Salus Architecture

Salus is a docker container. Installed into the container are security scanners and a small ruby application that coordinates them.

![Salus Architecture Diagram](salus_architecture.png)

The source code being scanned is volumed into the container and Salus expects to find this code at the internal path `/home/repo`. While the Salus application is written in Ruby, other languages are installed in the container as required for each scanners.

## Ruby Objects

  - [`Salus`](../lib/salus.rb): the primary class of the application.
  - [`Salus::CLI`](../lib/salus/cli.rb): command line wrapper to run Salus.
  - [`Salus::Config`](../lib/salus/config.rb): object that maintains Salus' configuration.
  - [`Salus::Processor`](../lib/salus/processor.rb): runs each scanners against the repo.
  - [`Salus::Repo`](../lib/salus/repo.rb): representation of the repository being scanned.
  - [`Salus::Report`](../lib/salus/report.rb): object that collects data about scans and compiles a report.
  - [`Salus::Scanners::<name>`](../lib/salus/scanners): scanner objects that can determine if a scanner should run, runs the scanner and collect the results.

## Plugins

Filters

Salus::PluginManager.apply_filter(:salus_config, :filter_config, config_hash)
Salus::PluginManager.apply_filter(:salus_report, :filter_report_hash, report_hash)

Events

Salus::PluginManager.send_event(:cli, :startup, ARGV)
Salus::PluginManager.send_event(:cli, :scan, options)
Salus::PluginManager.send_event(:salus, :scan, method(__method__).parameters)
Salus::PluginManager.send_event(:salus_processor, :skip_scanner, scanner_name)
Salus::PluginManager.send_event(:salus_processor, :run_scanner, scanner_name)
Salus::PluginManager.send_event(:salus_processor, :scanners_ran, scanners_ran)
Salus::PluginManager.send_event(:salus_scanner_base, :run_shell, command)