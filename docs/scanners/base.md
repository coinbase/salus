# `Salus::Scanners::Base`

The parent class of all scanners. Contains methods useful for executing scanners and reporting results.

## Config global to all scanners

##### Custom Failure Messages

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
