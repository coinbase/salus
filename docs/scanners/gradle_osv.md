# Gradle OSV Scanner

Finds vulnerable dependencies in a Gradle project. By default, GradleOSV Scanner pulls advisory information from [OSV - Database for open source vulnerabilities](https://osv.dev/) to compare against the dependencies found by running `gradle dependencies`.

## Configuration

To enable Gradle Scanning, add the following configuration to build.gradle for repo with single project or a repo with multiple sub projects.
```java
# Single Project setup
task reportDependencies(type: reportDependencies) {}

# Muti Project setup
subprojects {
    task allDeps(type: DependencyReportTask) {}
}
```

When a CVE is present in a dependency, the best course of action is to upgrade the dependency to a patched version. However, if there is currently no patch available or its a false positive you can use the following configuration option to ignore a particular CVE.

```yaml
scanner_configs:
  GradleOSV:
    exceptions:
      - advisory_id: CVE-2020-26945
        changed_by: security-team
        notes: Currently no patch exists and determined that this vulnerability is not exploitable.
        expiration: "2022-12-31"
```
