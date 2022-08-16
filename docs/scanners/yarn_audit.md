# [YarnAudit](https://yarnpkg.com/lang/en/docs/cli/audit/)

### [Legacy Yarn (< 2.0.0)](https://classic.yarnpkg.com/en/docs/cli/audit/)

### [Latest Yarn (> 2.0.0)](https://yarnpkg.com/cli/npm/audit)

Finds CVEs in Node modules included as dependencies in a project that is packaged by Yarn.

This scanner allows you to select which types of dependencies to exclude. By default, all dependencies are included.

See <https://yarnpkg.com/lang/en/docs/dependency-types/> for more info on dependency types.

```yaml
scanner_configs:
  YarnAudit:   
    exclude_groups:
      # Including all 3 effectively disables yarn as yarn audit is a CVE scanner on dependencies
    - dependencies            # project dependencies
    - devDependencies         # dev only dependencies
    - optionalDependencies    # specifically labelled as optional
    exceptions:
    - advisory_id: 788
      changed_by: Appsec team
      notes: Temporary exception generated automatically
      expiration: "2021-04-27"
```

If you want salus to autofix the yarn dependency files, then set `auto_fix: true`.
> NOTE: Only availabe for yarn > 2.0.0.

```yaml
scanner_configs:
  YarnAudit:
    auto_fix: true
```

If you only want to scan production-related dependencies, then you want the following:

```yaml
scanner_configs:
  YarnAudit:
    exclude_groups:
    - devDependencies         # dev only dependencies
```

If you only want to scan transitive dependencies, then you want the following:
> NOTE: Only availabe for yarn > 2.0.0

```yaml
scanner_configs:
  YarnAudit:
    scan_depth: 
     - recursive               # recurse and scan transitive dependencies
```

See [NodeAudit](/docs/scanners/node_audit.md) doc for more configuration options.
