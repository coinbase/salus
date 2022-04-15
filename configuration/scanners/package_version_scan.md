---
icon: dot
---
# Package Version Scanning

These scanners checks whether a repository's package version is within a range of configured versions. This allows you to block certain versions of a package or dependency in your project. 

Salus currently supports the following Package Version Scanners
- NPMPackageScanner 
- GoPackageScanner
- RubyPackageScanner

---
## Configuration Options

### package_versions
=== package_versions : `Hash`

for each `package_name`, users may configure the `min_version`, `max_version` or `blocks` options

Options | Description
--- | ---
`min_version` | This is a Semantic Version String which indicates the Minimum version of a package allowed in the project
`max_version` | This is a Semantic Version String which indicates the Maximum version of a package allowed in the project
`blocks` | This is a Semantic Version String which indicates specific versions of a package to restrict from a project. 

```yml
scanner_config:
  GoPackageScanner:
    package_version:
      package_name:
        min_version: '3.1.0'
        max_version: '3.10.3'
        blocks: '3.2.0, 3.3.0'
```
===

---

## Sample Configuration
Here is an example of how to provide version configuration in a salus config file

```sh salus.yml
scanner_configs:
  NPMPackageScanner:
    package_versions:
      xregexp:
        min_version: '3.1.0'
        max_version: '3.10.3'
        blocks: '3.2.0, 3.3.0'
      faker:
        min_version: '0.1.0'
        max_version: '1.10.3'
        blocks: '0.2.0'
 GoPackageScanner:
    package_versions:
      gopkg.in/yaml.v2:
        min_version: '2.0.0'
        blocks: '2.1.0'
      github.com/gin-gonic/gin:
        min_version: '1.1.0'
        max_version: '2.0.0'
        blocks: '1.5.0, 1.6.0'
  RubyPackageScanner:
    package_versions:
      actioncable:
        max_version: '8.0.0'
        blocks: '7.0.2.2'
```

---