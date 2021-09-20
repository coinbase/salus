# [Cargo Audit](https://github.com/RustSec/cargo-audit)

Audit Cargo.lock files for crates with security vulnerabilities reported to the RustSec Advisory Database.

## Configuration

When a CVE is present in a dependency, the best course of action is to upgrade the dependency to a patched version. Conveniently, you can run `cargo audit fix` which will try to find a compatible and patched version of the module.

This might not be possible if there is no patched version available yet or if the upgraded version is not compatible with your project. Provided that the vulnerability is not relevant to the way in which you use this dependency, you might want Salus to ignore this particular CVE. Use the following configuration to achieve this:

Some warnings may lack a CVE advisory id.  Warnings lacking an advisory id can be disabled by setting elevate_warnings to false.  The elevate_warning setting is used to elevate warnings (yanked or unmaintained repos) to errors (default).
```yaml
scanner_configs:
  CargoAudit:
    elevate_warnings: true
    exceptions:
      - advisory_id: RUSTSEC-2019-0010
        changed_by: security-team
        notes: Currently no patch exists and determined that this vulnerability is not exploitable.
        expiration: "2021-04-27"
```