# [sgrep](https://sgrep.dev)

[`sgrep`](https://sgrep.dev) (syntactic grep) is an open-source tool for finding patterns in code. It's useful for preventing the use of known anti-patterns in a codebase or enforcing the correct use of secure-by-default frameworks (e.g. always use a project's sanitization method on user-provided data).

sgrep is fast and powerful; it's grep-esque patterns are lifted into AST matchers. Compared to regexes these patterns aren’t affected by whitespaces, comments, newlines, the order of keyword arguments, variable renaming, and other language nuances.

If a found pattern is forbidden this scanner will fail and the `message` will be show to the developer in the report. A `required` pattern must be found in order for the scan to pass

## Configuration

```yaml
scanner_configs:
  config:
    matches:
      - pattern: $X == $X
        message: Useless equlity check
        language: python
      - pattern: $X.unsanitize(...)
        message: Don't call `unsanitize()` methods without careful review
        language: js
        forbidden: true
```
