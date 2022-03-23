# Package Version Scan

This scanner checks whether repository's package version is - 
 - Within a range of configured versions.
 - Matches any blocked configured versions.
 
The user may provide custom min_version, max_version, blocks for different packages using custom configurations.

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
 GoPackageScanner:
    package_versions
      gopkg.in/yaml.v2:
        min_version: '2.0.0'
        blocks: '2.1.0'
      github.com/gin-gonic/gin:
        min_version: '1.1.0'
        max_version: '2.0.0'
        blocks: '1.5.0, 1.6.0'
  RubyPackageScanner:
    package_versions
      actioncable:
        max_version: '8.0.0'
        blocks: '7.0.2.2'
```

For now, we only support following version scanners:

```
  NPMPackageScanner
  GoPackageScanner
  RubyPackageScanner
```