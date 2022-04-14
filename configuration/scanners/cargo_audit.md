---
icon: dot
tags: [config, scanner]
---
# [Cargo Audit](https://github.com/RustSec/cargo-audit)

Audit Cargo.lock files for crates with security vulnerabilities reported to the RustSec Advisory Database.

## Configurations
In addition to the [global scanner configurations](/configuration/scanners/), the Cargo Audit scanner has it's specific configurations available. 

The following configuration options are available for the CargoAudit scanner.


### elevate_warnings
=== elevate_warnings: `bool`
Some warnings may lack a CVE advisory id.  Warnings lacking an advisory id can be disabled by setting elevate_warnings to false.  The elevate_warning setting is used to elevate warnings (yanked or unmaintained repos) to errors (default).

```yml
elevate_warnings: true
```

===
---

## Sample Configuration for Scanner
```yaml salus.yml
scanner_configs:
  CargoAudit:
    elevate_warnings: true
    exceptions:
      - advisory_id: RUSTSEC-2019-0010
        changed_by: security-team
        notes: Currently no patch exists and determined that this vulnerability is not exploitable.
        expiration: "2021-04-27"
```