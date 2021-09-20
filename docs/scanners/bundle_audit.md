# [Bundle Audit](https://github.com/rubysec/bundler-audit)

Finds CVEs in Ruby gems included in a project.

## Configuration

When a CVE is present in a dependency, the best course of action is to upgrade the dependency to a patched version. However, if there is currently no patch available, this will not be possible. Provided that the vulnerability is not relevant to the given project, you might want Salus to ignore this particular CVE.

BundleAudit has a `--ignore` flag which allows you to ignore particular CVEs. To list CVEs that should be ignored, you can add a list to the Salus config.

```yaml
scanner_configs:
  BundleAudit:
    ignore: # deprecated CVE allowlisting format please use exceptions
      - CVE-2018-3760
      - CVE-XXXX-YYYY

    exceptions:
      - advisory_id: CVE-2018-3760
        changed_by: security-team
        notes: Currently no patch exists and determined that this vulnerability is not exploitable.
        expiration: "2021-04-27"
```

By default, BundleAudit pulls advisory info from [ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db).
BundleAudit also supports scanning against a local advisory DB.  The config below will scan against the local DB in addition to ruby-advisory-db.
The `$local_db_dir` should follow the same format as the ruby-advisory-db.
This means that at the top-level, there should be a `gems` dir, each sub-directory inside `gems` should have the same name as an actual gem,
and each gem directory should contain the advisory yml's.
```yaml
scanner_configs:
  BundleAudit:
    local_db: $local_db_dir
```

## Exceptions

The ignore configuration is supported for backwards compatibility and will be deprecated in the future.  Salus exceptions are being normalized to the new exceptions configuration