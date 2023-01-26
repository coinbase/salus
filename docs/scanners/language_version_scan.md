# Language Version Scan

This scanner checks whether repository's programming language version is within the range of configured versions. The user may provide min_version and max_version using custom configuration. 

Following is an example of how the user can provide version configuration in `salus.yaml` file.

```sh
scanner_configs:
  GoVersionScanner:
    info:
      min_version: '1.20.0'
      max_version: '1.25.0'
    block:
      min_version: '1.18.0'
```

For now, we only support following version scanners:

```
  GoVersionScanner
  RubyVersionScanner
```