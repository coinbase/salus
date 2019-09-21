# [Gosec](https://github.com/securego/gosec)

The [Gosec Scanner](https://github.com/securego/gosec) is a static analysis tool that finds vulnerabilities in Go projects using the Go AST. Gosec supports Go modules as of Gosec 2.0.0.


## Configuration
```yaml
  Gosec:
    scanner_configs:
    - nosec: false                        # default -  Ignores #nosec comments when set
      nosec-tag: falsepositive            # Set an alternative string for #nosec (default)
      conf: conf.json                     # Path to optional config file
      include:                            # List of rules IDs to include
        - G104                            # Note only basic regex formatting is performed and does  
                                          # not check if this is a valid rule number
      exclude:                            # List of rules IDs to exclude
        - G102
      sort: true                          # Sort issues by severity
      tags:                               # List of build tags
        - tag1
        - tag2
      severity: low                      # Filter out the issues with a lower severity than the
                                         # given value. Valid options are: low, medium, high
      confidence: low                    # Filter out the issues with a lower confidence than the
                                         # given value. Valid options are: low, medium, high
      no-fail: false                     # Do not fail the scanning, even if issues were found
      tests: false                       # Scan tests files
      exclude-dir:                       # exclude the folders from scan can be files or directories
        - tests/
        - temp/
        - vendor/
        - temp.go
```
