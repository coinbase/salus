# [Bandit](https://pypi.org/project/bandit/)

The [Bandit Scanner](https://pypi.org/project/bandit/) is a static analysis tool that finds common security vulnerabilities in Python code.
Salus will run the Bandit scanner if your repo has a setup.cfg or requirements.txt.

## Configuration

Bandit currently always runs with the `--recursive` and `--format json` options turned on.
In addition, you can configure the additional options below.
For more information on Bandit configs, see [Bandit Usage](https://pypi.org/project/bandit/#usage)

```yaml
  scanner_configs:
    Bandit:
      aggregate: file or vuln  # aggregate output by vulnerability (default) or by filename
      configfile: config_filename  # config file to use for selecting plugins and overriding defaults
      profile: profile_name"  # "profile to use (defaults to executing all tests)"
      tests:  # list of test IDs to run
        - test_id1
        - test_id2
      skips:  # list of test IDs to skip
        - test_id1
        - test_id2
      level: LOW or MEDIUM or HIGH  # report only issues of given severity level or higher, default is LOW
      confidence: LOW or MEDIUM or HIGH  # report only issues of given confidence level or higher, default is LOW
      baseline: baseline_report_filename  # path of a baseline report to compare against
      ini: path_to_.bandit_file  # file supplies command line args
      ignore-nosec: true or false  # do not skip lines with # nosec comments
      exclude: # paths to exclude from scan
        - path1
        - path2
      exceptions:
        - advisory_id: test_id1
          changed_by: security-team
          notes: Currently no patch exists and determined that this vulnerability is not exploitable.
          expiration: "2021-04-27"
```

The following Bandt config options are currently NOT supported.
```yaml
-n CONTEXT_LINES   # maximum number of code lines to output for each issue
--format {csv,custom,html,screen,txt,xml,yaml}   # salus always writes output to json
--msg-template MSG_TEMPLATE   # unsupported because it only works with --format custom
--verbose  # output extra information like excluded and included
--debug  # turn on debug mode (used for debugging Bandit code)
--quiet  # only show output in the case of error
```

## Exceptions

The skips configuration is supported for backwards compatibility and will be deprecated in the future.  Salus exceptions are being normalized to the new exceptions configuration