# [YarnAudit](https://yarnpkg.com/lang/en/docs/cli/audit/)

Finds CVEs in Node modules included as dependencies in a project that is packaged by Yarn.

This scanner allows you to select which types of dependencies to exclude. By default, all dependencies are included.

See https://yarnpkg.com/lang/en/docs/dependency-types/ for more info on dependency types.

```yaml
scanner_configs:
  YarnAudit:
    exclude_groups:
      # Including all 3 effectively disables yarn as yarn audit is a CVE scanner on dependencies
    - dependencies            # project dependencies
    - devDependencies         # dev only dependencies
    - optionalDependencies    # specifically labelled as optional
```

If you only want to scan production-related dependencies, then you want the following:
```yaml
scanner_configs:
  YarnAudit:
    exclude_groups:
    - devDependencies         # dev only dependencies
```
See [NodeAudit](/docs/scanners/node_audit.md) doc for more configuration options.
