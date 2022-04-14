---
label: Scanners
icon: codescan
tags: config
---
# Scanner Configurations
Salus will read your `salus config` file 
The configurations on this page are available for all Salus scanners and these can be used in the salus config file to configure your desired scanners. Each scanner may also have scanner specific configuration available solely for that scanner. 

!!!
In addition to these configurations, you can also create your [custom configurations](/guides/development/custom_configurations/) for salus or [add additional scanners](/guides/development/adding_custom_scanners/) to salus
!!!

---

You'll need to specify your scanner and its configuration in a config file to use these configurations. Here the config file used was `salus.yml`
```yml salus.yml
scanner_configs:
  YarnAudit:
    pass_on_raise: true
```

In your salus config file, you can add configurations for multiple salus scanners 
```yml salus.yml
scanner_configs:
  YarnAudit:
    pass_on_raise: true
  NPMAudit:
    pass_on_raise: true
```
---
## exceptions
=== exceptions: `Array`

When a CVE is present in a dependency, the best course of action is to upgrade the dependency to a patched version. However, if there is currently no patch available or it's a false positive, you can use the following configuration option to ignore a particular CVE. Salus provides an option to ignore these CVEs using the [exceptions](#exceptions) option

The `advisory_id` , `changed_by`  and `notes` are required fields.

Option | Type | Description
--- |   --- |   ---
`advisory_id` | `string` | CVE you want to ignore
`changed_by` | `string` | name of the person who made the change
`notes` | `string` | Any additional notes or reasons why this CVE was ignored
`expiration` | `string` | This is an optional field that identifies the expiration date for the exception

```yml
scanner_config:
  exceptions:
    - advisory_id: CVE-2090-9090
      changed_by: John Doe
      notes: Currently no patch exists and determined that this vulnerability is not exploitable.
      expiration: "2025-04-27"
    - advisory_id: CVE-2090-9091
      changed_by: John Doe
      notes: Currently no patch exists and determined that this vulnerability is not exploitable.
      expiration: "2025-05-27"
```

!!!warning Support
The following Scanners currently do not support this configuration option
- [Dependency Scanners](/configuration/scanners/dependency_scanners)
- [RepoNotEmpty](/configuration/scanners/repository_not_blank/)

!!!
===

---

## failure_message
=== failure_message : `string`
You can define a custom message to be shown to the developer when the given scanner fails. This is useful for pointing developers to internal security resources or teams that can help address the failure.

Example with `BundleAudit` configuration:

```yml salus.yml
scanner_configs:
  BundleAudit:
    failure_message: |
      A CVE was found in one of your gems. Please try to upgrade the offending gem.
        $ bundle update <gem name>

      If this does not resolve the error, seek advice from the security team.
      Slack channel: #security
```
===

---
## pass_on_raise
=== pass_on_raise: `bool`

Some scanners are very resilient and it's rare for them to throw exceptions. Usually, this is for a good reason, like a malformed file is unparsable by the scanner and so this warrants breaking the project's build. By default, if a scanner raises an exception for whatever reason, then the scanner is considered _failed_ as if it found an actual security issue.

However, some scanner fail frequently for reasons out of the developer's control. For example, a CVE registry might be down which means that a CVE scanner cannot update it's local DB and this causes it to raise an error. In that scenario, you might decide that Salus's overall status, and therefore the CI/CD pipeline should not fail. To allow for a scanner to be considered a _pass_ when it raises an exception, you can provide the value `true` for the directive `pass_on_raise`. For example:

```yml salus.yml
scanner_configs:
  YarnAudit:
    pass_on_raise: true
```
!!!
When this is set to true, any errors thrown by the scanner will still be recorded in the report.
!!!
===

---

## recursion
=== recursion: `Hash`
optional recusion settings. 

Options | Description
--- | ---
`directory_exclusions` | Directories to exclude when recursing. Any matches that occur in the list of directory_exclusions will be ignored
`directories` | Directories to recurse into.  When present, any directories that need to be scanned should explicitly listed
`directories_matching` |  Dynamically identify directories to recurse into. Each entry may have a combination of filename and or content.  Filename matches on the name of the file, while content matches on the content within the file.
`static_files` | Files to copy from the root directory to recursed directories. This can be useful for mono repositories where a common file should be copied to subdirectories for proper scanning.

```yml
scanner_configs:
  BundleAudit:
    recursion:   
      directory_exclusions: 
        - vendor
      directories: 
        - ./
        - payments/lhv
        - infra/sso/identity_provider
      directories_matching: 
        - filename: "BUILD.bazel"
          content: "bundle//:rails"
        - filename: "package.json"
      static_files: 
        - Gemfile
        - Gemfile.lock
```
===

---

## scanner_timeout_s
=== scanner_timeout_s: `Hash`
At times, scanners may perform scans for unacceptable lengths of time. To limit this behavior, you can define `scanner_timeout_s` with the number of seconds you wish the scan to last before it times out.  

Example with `YarnAudit` configuration:

```yml salus.yml
scanner_configs:
  YarnAudit:
    scanner_timeout_s: 60
```

This will limit YarnAudit scans to 1 minute (60 seconds) in execution time.

---
