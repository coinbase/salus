# Slither Scanner

Performs static analysis on solidity code.
Only projects that use truffle or hardhat configs are supported.

## Configuration

```yaml
scanner_configs:
  Slither:
    filter-paths: a.sol|b.sol  # exclude file/dir paths, separate with |
```

* `filter-paths` - `path1` will exclude all the results that are only related to path1. The path specified can be a path directory or a filename. Direct string comparison and [Python regular expression](https://docs.python.org/3/library/re.html) are used.  For example, the value could be `a.sol` or a regular expression like `a.sol|b.sol`.
