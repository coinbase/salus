---
icon: dot
---
# [YarnAudit](https://yarnpkg.com/lang/en/docs/cli/audit/)

Finds CVEs in Node modules included as dependencies in a project that is packaged by Yarn.

This scanner allows you to select which types of dependencies to exclude. By default, all dependencies are included.

See https://yarnpkg.com/lang/en/docs/dependency-types/ for more info on dependency types.


---


---

## Configuration
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

If you only want to scan production-related dependencies, then you want the following:
```yaml
scanner_configs:
  YarnAudit:
    exclude_groups:
    - devDependencies         # dev only dependencies
```
See [NodeAudit](/configuration/scanners/node_audit/) doc for more configuration options.
