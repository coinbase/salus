# Misnamed Configuration

This scanner asserts that no `salus.yml` file exists within the repository root. It's common for developers to mistake the `salus.yml` filename for the correct `salus.yaml`. This scanner helps detect those issues

For example, the scanner would pass on a `my_repository` repo with the following structure.
```
my_repository
   ├── my_script.rb
   └── salus.yaml
```

However, it would fail on a `my_repository` repo with the following structure.
```
my_repository
   ├── my_script.rb
   └── salus.yml
```
