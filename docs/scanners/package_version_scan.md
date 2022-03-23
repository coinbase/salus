# Package Version Scan

This scanner checks whether repository's package version is within the range of configured versions or part of blocked version. The user may provide custom min_version, max_version, blocks for different packages using custom configurations

Following is an example of how the user can provide version configuration in `salus.yaml` file.

```sh
scanner_configs:
  NPMPackageScanner:
    package_versions
      xregexp:
        min_version: '3.1.0'
        max_version: '3.10.3'
        blocks: '3.2.0, 3.3.0'
      faker:
        min_version: '0.1.0'
        max_version: '1.10.3'
        blocks: '0.2.0'
  RubyPackageScanner:
    package_versions
      actioncable:
        max_version: '8.0.0'
        blocks: '7.0.2.2'
```

For now, we only support following version scanners:

```
  NPMPackageScanner
  RubyPackageScanner
```