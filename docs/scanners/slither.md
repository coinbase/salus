# Slither Scanner

Performs static analysis on solidity code.
Only projects that use truffle or hardhat configs are supported.

## Configuration
```yaml
scanner_configs:
  Slither:
    filter-paths: file1.sol|file2.sol  # exclude file/dir paths, separate with |
```