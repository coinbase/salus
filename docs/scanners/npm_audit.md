# [NPM Audit](https://docs.npmjs.com/getting-started/running-a-security-audit)

Finds CVEs in Node modules included as dependencies in a project.

## Configuration

When a CVE is present in a dependency, the best course of action is to upgrade the dependency to a patched version. Conveniently, you can run `npm audit fix` which will try to find a compatible and patched version of the module.

Sometimes, a patched module might not exist and so you will have to assess if the vulnerability is relevant to the way you use the module. If you determine that this CVE is not a concern, then you can tell Salus to ignore this finding with the configuration below.

This might not be possible if there is no patched version available yet or the upgraded version cannot be used in the project for conflicting reasons. Provided that the vulnerability is not relevant to the given project, you might want to the scanner to ignore this particular CVE.

```yaml
scanner_configs:
  NPMAudit:
    exceptions:
      - advisor_id: 39
        changed_by: security-team
        notes: Currently no patch exists and determined that this vulnerability is not exploitable.
```
