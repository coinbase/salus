# Package Version Scan

This scanner checks whether repository's package version is within the range of configured versions. The user may provide custom min_version and max_version for different packages using custom configurations

Following is an example of how the user can provide version configuration in `salus.yaml` file.

```sh
scanner_configs:
  NPMPackageScanner:
    package_versions
      xregexp:
        min_version: '3.1.0'
        max_version: '3.10.3'
      faker:
        min_version: '0.1.0'
        max_version: '1.10.3'
```

For now, we only support following version scanners:

```
  NPMPackageScanner
```