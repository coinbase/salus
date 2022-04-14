---
icon: dot
tags: [config, scanner]
---
# Language Version Scan

This scanner checks whether repository's programming language version is within the range of configured versions. 

Salus Currently Supports the following Language Version Scanners

- GoVersionScanner
- RubyVersionScanner

## Configuration
In addition to the [global scanner configurations](/configuration/scanners/), Language Version Scanners have their own specific configurations available. 

The user may provide min_version and max_version for each scanner. 

Option | Description
--- | ---
`max_version` | This is a Semantic version string, indicating the minimum version of a language that should be allowed in a project
`max_version` | This is a Semantic version string, indicating the minimum version of a language that should be allowed in a project


---
## Sample Scanner Configuration
The following is an example of how the user can provide version configuration in `salus.yaml` file.
```yml Configuring GoLang 
scanner_configs:
  GoVersionScanner:
    min_version: '1.18.0'
    max_version: '1.20.3'
```

```yml Configuring GoLang and Ruby
scanner_configs:
  GoVersionScanner:
    min_version: '1.18.0'
    max_version: '1.20.3'
  RubyVersionScanner:
    min_version: '3.0.0'
```
