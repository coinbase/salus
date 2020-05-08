# [semgrep](https://semgrep.dev)

[`semgrep`](https://semgrep.dev) (syntactic grep) is an open-source tool for finding patterns in code. It's useful for preventing the use of known anti-patterns in a codebase or enforcing the correct use of secure-by-default frameworks (e.g. always use a project's sanitization method on user-provided data).

semgrep is fast and powerful; it's grep-esque patterns are lifted into AST matchers. Compared to regexes these patterns aren’t affected by whitespaces, comments, newlines, the order of keyword arguments, variable renaming, and other language nuances.

If a found pattern is forbidden this scanner will fail and the `message` will be show to the developer in the report. A `required` pattern must be found in order for the scan to pass.

There is also a `exclude_directory` option for excluding directories -- the glob pattern will match anywhere in the directory so for example `exclude_drectory: [node_modules]` will ignore both `./node_modules`, `lib/node_modules`, and `demo/demo2/node_modules`.

## Configuration

```yaml
scanner_configs:
  Semgrep:
    matches:
      - pattern: $X == $X
        message: Useless equlity check
        language: python
        exclude_directory:
          - tests
      - pattern: $X.unsanitize(...)
        message: Don't call `unsanitize()` methods without careful review
        language: js
        forbidden: true
```
