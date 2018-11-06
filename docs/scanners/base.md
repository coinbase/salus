# `Salus::Scanners::Base`

The parent class of all scanners. Contains methods useful for executing scanners and reporting results.

## Config global to all scanners

#### Pass on Raise

Some scanners are very resilient and it's rare for them to throw exceptions. Usually this is for good reason, like a malformed file is unparsable by the scanner and so this warrants breaking the project's build. By default, if a scanner raises an exception for whatever reason, then the scanner is conidered _failed_ as if it found an actual security issue.

However, some scanner fail frequently for reasons out of the developer's control. For example, a CVE registry might be down which means that a CVE scanner cannot update it's local DB and this causes it to raise an error. In that scenario, you might decide that Salus's overall status, and therefore the CI/CD pipeline should not fail. To allow for a scanner to be considered a _pass_ when it raises an exception, you can provide the value `true` for the directive `pass_on_raise`. For example:

```yaml
scanner_configs:
  YarnAudit:
    pass_on_raise: true
```

When this is set to `true`, any errors thrown by the scanner will still be recorded in the report.

#### Custom Failure Messages

You can define a custom message to be shown to the developer when the given scanner fails. This is useful for pointing developers to internal security resources or teams that can help address the failure.

Example with `BundleAudit` configuration:

```yaml
scanner_configs:
  BundleAudit:
    failure_message: |
      A CVE was found in one of your gems. Please try to upgrade the offending gem.
        $ bundle update <gem name>

      If this does not resolve the error, seek advice from the security team.
      Slack channel: #security
```
