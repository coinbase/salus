# [semgrep](https://semgrep.dev)

[`semgrep`](https://semgrep.dev) (syntactic grep) is an open-source tool for finding patterns in code. It's useful for preventing the use of known anti-patterns in a codebase or enforcing the correct use of secure-by-default frameworks (e.g. always use a project's sanitization method on user-provided data).

semgrep is fast and powerful; it's grep-esque patterns are lifted into AST matchers. Compared to regexes these patterns aren’t affected by whitespaces, comments, newlines, the order of keyword arguments, variable renaming, and other language nuances.

If a found pattern is forbidden this scanner will fail and the `message` will be show to the developer in the report. A `required` pattern must be found in order for the scan to pass.

There is also a `exclude_directory` option for excluding directories -- the glob pattern will match anywhere in the file path parts so for example `exclude_drectory: [node_modules]` will ignore both `./node_modules`, `lib/node_modules`, and `demo/demo2/node_modules`. Passing in full paths such as `exclude_drectory: [lib/node_modules]` is not supported.

There is also support for external config files / registry keys under a `config` key. Any value entered here will directly be passed to `semgrep` and override `pattern`, `language`, and `message`.

## Configuration

```yaml
scanner_configs:
  Semgrep:
    matches:
      - pattern: $X == $X
        message: Useless equlity check
        language: python
        forbidden: true
        exclude_directory:
          - tests
      - pattern: $X.unsanitize(...)
        message: Don't call `unsanitize()` methods without careful review
        language: js
        forbidden: true
        exclude_directory:
          - node_modules
      - pattern: $LOG_ENDPOINT = os.getenv("LOGGER_ENDPOINT", ...)
        message: All files need to get the dynamic logger. Please don't hardcode this.
        language: python
        required: true
      - config: .semgrep.yml
        required: true
```
