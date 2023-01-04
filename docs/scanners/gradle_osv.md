# Gradle OSV Scanner

Finds vulnerable dependencies in a Gradle project. By default, GradleOSV Scanner pulls advisory information from [OSV - Database for open source vulnerabilities](https://osv.dev/) to compare against the dependencies found by running `gradle dependencies`.

## Configuration

When a CVE is present in a dependency, the best course of action is to upgrade the dependency to a patched version. However, if there is currently no patch available or its a false positive you can use the following configuration option to ignore a particular CVE.

```yaml
scanner_configs:
  GradleOSV:
    multi_project_build: true # If you run a multi project build setup, you can multi as true. Default is false
    exceptions:
      - advisory_id: CVE-2020-26945
        changed_by: security-team
        notes: Currently no patch exists and determined that this vulnerability is not exploitable.
        expiration: "2022-12-31"
```
