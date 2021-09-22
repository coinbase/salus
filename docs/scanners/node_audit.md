# [NodeAudit](https://docs.npmjs.com/getting-started/running-a-security-audit)

Finds CVEs in Node modules included as dependencies in a project.

`NodeAudit` is a superclass scanner for `YarnAudit` (executes `yarn audit`) and `NPMAudit` (executes `npm audit`).

## Configuration

When a CVE is present in a dependency, the best course of action is to upgrade the dependency to a patched version. Conveniently, you can run `npm audit fix` which will try to find a compatible and patched version of the module. If you're using `yarn` you will have to try upgrading manually.

This might not be possible if there is no patched version available yet or if the upgraded version is not compatible with your project. Provided that the vulnerability is not relevant to the way in which you use this dependency, you might want Salus to ignore this particular CVE. Use the following configuration to achieve this.

```yaml
scanner_configs:
  NodeAudit:
    exceptions:
      - advisory_id: 39
        changed_by: security-team
        notes: Currently no patch exists and determined that this vulnerability is not exploitable.
        expiration: "2021-04-27"
```

__NOTE__
To allow for backwards compatibility and easy switching between NPM and Yarn, Salus will merge configuration for `NodeAudit`, `NPMAudit` and `YarnAudit` into a single object to configure the `NodeAudit` scanner.
