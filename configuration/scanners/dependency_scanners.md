---
icon: dot
tags: [config, scanner]
---
# Dependency Scanners

These scanners are used to report modules or dependencies found in a project.  

Salus currently provides scanners to report dependencies found in different projects. Each scanner requires certain dependency files to be present before they are triggered

Language | Scanner | Description
:---: | :---: | :---:
Golang | `ReportGoDep`| This dependency reporter or scanner is triggered  when a Gopkg.lock go.mod go.sum file is present in project
Java | `ReportGradleDeps`, `ReportPomXml`  | These dependency reporters are triggered  when a `pom.xml` file is present in project 
JavaScript | `ReportNodeModules` | This dependency reporter or scanner is triggered  when a `package-lock.json`, `package.json` or `bower.json` are present
Python | `ReportPythonModules` | This dependency reporter or scanner is triggered  when a `requirements.txt` file is present
Rust | `ReportRustCrates` |  This dependency reporter or scanner is triggered  when a `Cargo.toml` or `Cargo.lock` file present
Ruby | `ReportRubyGems`  | This dependency reporter or scanner is triggered  when a `Gemfile` Present
Swift | `ReportPodfileLock`, `ReportSwiftDeps` | triggered  when a `Package.resolved` or `Podfile.lock` file is present


---
## Configurations

In addition to the [global scanner configurations](/configuration/scanners/), Dependency Scanner have their own specefic configurations available. 

The following configuration options are available for the Dependency scanners.

---
### include_dev_deps
=== include_dev_deps : `bool`

This config option allows user to include or exclude development dependencies in the reporting. The Default behavior in Salus assumes `include_dev_deps` as `true`.

Here is an example of how the user can provide `include_dev_deps` in a `salus.yml` file.


```yml
scanner_configs:
  ReportNodeModules:
    include_dev_deps: true
```
!!!
For now, Salus only supports this config option on the ReportNodeModules scanner
!!!
===
