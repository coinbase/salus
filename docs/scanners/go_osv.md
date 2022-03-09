# Golang OSV Scanner

Finds vulnerable dependencies in a Golang project. By default, GoOSV Scanner pulls advisory information from [OSV - Database for open source vulnerabilities](https://osv.dev/) to compare against the dependencies found in `go.sum`.

## Configuration

When a CVE is present in a dependency, the best course of action is to upgrade the dependency to a patched version. However, if there is currently no patch available or its a false positive you can use the following configuration option to ignore a particular CVE.

```yaml
scanner_configs:
  GoOSV:
    exceptions:
      - advisory_id: CVE-2020-26945
        changed_by: security-team
        notes: Currently no patch exists and determined that this vulnerability is not exploitable.
        expiration: "2022-12-31"
```
