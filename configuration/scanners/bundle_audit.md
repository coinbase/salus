---
icon: dot
tags: [config, scanner]
---
# [Bundle Audit](https://github.com/rubysec/bundler-audit)

The Bundle Audit Scanner finds CVEs in Ruby gems included in a project.

## Configurations
In addition to the [global scanner configurations](/configuration/scanners/), the BundleAudit scanner has specific configurations available. 

The following configuration options are available for the bundle audit scanner.

---
### ignore
=== ignore: `string`
Ignore specific advisories
```yml
scanner_configs:
  BundleAudit:
    ignore: CVE-YYYY-XXXX
```
===


!!!warning
This option for ignoring vulnerabilities is deprecated in Salus, please use the [exceptions](/configuration/scanners/#exceptions) option instead
!!!
---

### local_db
=== local_db: `string`
By default, BundleAudit pulls advisory info from [ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db).
BundleAudit also supports scanning against a local advisory DB.  The config below will scan against the local DB in addition to ruby-advisory-db.

The `path/to/local/database` should follow the same format as the ruby-advisory-db.

This means that at the top-level, there should be a `gems` dir, each sub-directory inside `gems` should have the same name as an actual gem,
and each gem directory should contain the advisory yml's.
```yaml Configuring Local Advisory Database
scanner_configs:
  BundleAudit:
    local_db: path/to/local/database
```
===

---

### Sample Configuration for Scanner
```yaml salus.yml
scanner_configs:
  BundleAudit:
    local_db: path/to/local/database

    exceptions:
      - advisory_id: CVE-2018-3760
        changed_by: security-team
        notes: Currently no patch exists and determined that this vulnerability is not exploitable.
        expiration: "2021-04-27"
```