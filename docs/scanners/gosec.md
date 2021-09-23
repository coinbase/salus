# [Gosec](https://github.com/securego/gosec)

The [Gosec Scanner](https://github.com/securego/gosec) is a static analysis tool that finds vulnerabilities in Go projects using the Go AST. Gosec supports Go modules as of Gosec 2.0.0.


## Configuration
```yaml
  scanner_configs:
    Gosec:
    - nosec: false                        # default -  Ignores #nosec comments when set to true
      nosec-tag: falsepositive            # Set an alternative string for #nosec (default)
      # conf: conf.json                   # Unsupported due to upstream bug. Path to optional config file
      include:                            # List of rules IDs to include
        - G104                            # Note only basic regex formatting is performed and does  
                                          # not check if this is a valid rule number
      exclude:                            # List of rules IDs to exclude, deprecated in favor of exceptions
        - G102
      sort: true                          # Sort issues by severity
      #tags:                              # Unsupported due to upstream bug. List of build tags
      #  - tag1
      #  - tag2
      severity: low                      # Filter out the issues with a lower severity than the
                                         # given value. Valid options are: low, medium, high
      confidence: low                    # Filter out the issues with a lower confidence than the
                                         # given value. Valid options are: low, medium, high
      no-fail: false                     # Do not fail the scanning, even if issues were found
      tests: false                       # Scan tests files
      exclude-dir:                       # excludes only folders from scan (files are ignored)
        - tests
        - temp
        - vendor
      run_from_dirs:                     # run gosec from the specified subdirs only
        - subdir1                        # for now, any other gosec config will apply to all subdir runs
        - subdir2
      exceptions:
        - advisory_id: G101
          changed_by: security-team
          notes: Currently no patch exists and determined that this vulnerability is not exploitable.
          expiration: "2021-04-27"
```
## Exceptions

The exclude configuration is supported for backwards compatibility and will be deprecated in the future.  Salus exceptions are being normalized to the new exceptions configuration