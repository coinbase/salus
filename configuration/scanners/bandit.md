---
icon: dot
tags: [config, scanner]
---
# [Bandit](https://pypi.org/project/bandit/)

The [Bandit Scanner](https://pypi.org/project/bandit/) is a static analysis tool that finds common security vulnerabilities in Python code.
Salus triggers the Bandit scanner if your repo has a setup.cfg or requirements.txt.

## Configuration
In addition to the [global scanner configurations](/configuration/scanners/), the Bandit scanner has specific configurations available. Salus does a great job of providing support for most of these options.

In addition, you can configure the additional options below.
For more information about Bandit configurations, see [Bandit Usage](https://bandit.readthedocs.io/en/latest/)

!!!
Currently in Salus, Bandit runs with the `--recursive` and `--format json` options turned on. 
!!!

---

### aggregate

=== aggregate : `string`

aggregate output by vulnerability (default) or by filename. It can take the `string` values `file` or `vuln`

```yml
aggregate: file
```
===

---

### baseline

=== baseline: `string`

path of a baseline report to compare against

```yml
baseline: "path/to/file"
```
===

---

### confidence

=== confidence: `string`

identifies the confidence level, It can take the `string` options `LOW`, `MEDIUM` or `HIGH`. The default on Salus is `LOW`

```yml
confidence: MEDIUM
```
===

---
### configfile

=== configfile: `string`

Path to optional config file to use for selecting plugins and overriding defaults

```yml
configfile: file_name
```
===

---

### exclude

=== exclude : `list`

List of paths to exclude from scan

```yml
exclude: 
  - "path/to/file1"
  - "path/to/file2"
```
===

---

### ignore-nosec

=== ignore-nosec: `bool`

set to true if you want lines with #nosec comments to be skipped, false if otherwise

```yml
ignore-nosec: false
```
===

---

### ini

=== ini: `string`

path to a .bandit file that supplies command line arguments

```yml
aggregate: path/to/file.bandit
```
===

---

### level

=== level: `string`

report only issues of given severity level or higher. The valid values for this option are the `strings``LOW`, `MEDIUM` or `HIGH`

```yml
level: HIGH
```
===

---

### profile

=== profile: `string`

profile to use (defaults to executing all tests)

```yml
profile: profile_name
```
===

---

### skips
!!!warning 
**skips** is currently supported for backwards compatibility and will be deprecated in future versions of salus. This [**exceptions**](/configuration/scanners/#exceptions) option will replace this
!!!

=== skips : `list`

List of test IDs to skip.

```yml
skips: 
  - B101
  - B102
```
===

---

### tests

=== tests: `list`

list of test IDs to run

```yml
tests: 
  - B101
  - B102
```
===

---

## Sample Configuration for Scanner
Here is an example of how the options detailed above could be configured in a `salus.yml` file
```yaml salus.yml
  scanner_configs:
    Bandit:
      aggregate: file
      configfile: config_filename  
      profile: profile_name"  
      tests:
        - B101
        - B102
      skips: 
        - B101
        - B102
      level: LOW
      confidence: HIGH
      baseline: baseline_report_filename  
      ini: path_to_.bandit_file  
      ignore-nosec: true or false  
      exclude: 
        - path1
        - path2
      exceptions:
        - advisory_id: B101
          changed_by: security-team
          notes: Currently no patch exists and determined that this vulnerability is not exploitable.
          expiration: "2021-04-27"
```

---

## Unsupported Configurations
The following Bandit config options are currently NOT supported.
```yml
-n CONTEXT_LINES   # maximum number of code lines to output for each issue
--format {csv,custom,html,screen,txt,xml,yaml}   # salus always writes output to json
--msg-template MSG_TEMPLATE   # unsupported because it only works with --format custom
--verbose  # output extra information like excluded and included
--debug  # turn on debug mode (used for debugging Bandit code)
--quiet  # only show output in the case of error
```
