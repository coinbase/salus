# Slither Scanner

Performs static analysis on Solidity code. Only projects that use Truffle or Hardhat configs are supported.

## Configuration

```yaml
scanner_configs:
  Slither:
    filter-paths: a.sol|b.sol                  # Exclude file / directory paths, separated with |
    exclude-optimization: true                 # Ignore findings with optimization-level impact
    exclude-informational: true                # Ignore findings with informational-level impact
    exceptions:                                # Exclude the detectors(vulnerabilities)
      - advisory_id: incorrect-shift
        changed_by: appsec
        notes: This is false-positive
        expiration: '2200-12-31'
      - advisory_id: dead-code
        changed_by: appsec
        notes: This is false-positive
        expiration: '2200-12-31'
```

* `filter-paths` - `path1` will exclude all the results that are only related to path1. The path specified can be a path directory or a filename. Direct string comparison and [Python regular expression](https://docs.python.org/3/library/re.html) are used.  For example, the value could be `a.sol` or a regular expression like `a.sol|b.sol`.

* `exclude-optimization` - When `true`, this option enables the `--exclude-optimization` flag when invoking Slither and causes the scanner to ignore detectors that have `Optimization` level impact. By default, this option is set to `false`. A list of detectors and their impacts can be found in [the Slither README](https://github.com/crytic/slither/tree/168e96298fb8f8a588c110aa75cd38b3a7662ed9#detectors).

* `exclude-informational` - When `true`, this option enables the `--exclude-informational` flag when invoking Slither and causes the scanner to ignore detectors that have `Informational` level impact. By default, this option is set to `false`. A list of detectors and their impacts can be found in [the Slither README](https://github.com/crytic/slither/tree/168e96298fb8f8a588c110aa75cd38b3a7662ed9#detectors).

* `exceptions` - Using this option, any user can provide a list of detectors(vulnerabilities) that need to be excluded from the scan result.  A list of detectors and their impacts can be found in [the Slither README](https://github.com/crytic/slither/tree/168e96298fb8f8a588c110aa75cd38b3a7662ed9#detectors).
