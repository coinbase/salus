# Dependency Scanners

These scanners are used to report modules / dependencies found in a repository. The user may provide if they want dev dependencies to be included in the reporting or not using custom configuration.

Following is an example of how the user can provide `include_dev_deps` in `salus.yaml` file.
Default behavior assumes `include_dev_deps` as `true`.

```sh
scanner_configs:
  ReportNodeModules:
   include_dev_deps: true
```

For now, we only support this config option on the following scanners:

```
  ReportNodeModules
```