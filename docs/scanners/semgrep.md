# [semgrep](https://semgrep.dev)

[`semgrep`](https://semgrep.dev) (syntactic grep) is an open-source tool for finding patterns in code. It's useful for preventing the use of known anti-patterns in a codebase or enforcing the correct use of secure-by-default frameworks (e.g. always use a project's sanitization method on user-provided data).

semgrep is fast and powerful; it's grep-esque patterns are lifted into AST matchers. Compared to regexes these patterns aren’t affected by whitespaces, comments, newlines, the order of keyword arguments, variable renaming, and other language nuances.

Currently, the supported languages are: C, Go, Java, JavaScript, and Python.

## Configuration

There are two types of rules in Semgrep:

1) [Simple rules](https://github.com/returntocorp/semgrep#simple-rules) - expressed with a single `pattern`.
2) [Advanced rules](https://github.com/returntocorp/semgrep#advanced-rules) - expressed with multiple patterns, like: X must be true AND Y must be too, or X but NOT Y, or X must occur inside a block of code that Y matches.  These patterns are composed with the `patterns` keyword.

In salus.yaml, both simple and advanced rules can be specified with a path to a [Semgrep YAML config file](https://github.com/returntocorp/semgrep/blob/develop/docs/configuration-files.md).
In adddition, simple rules can be specified directly in salus.yaml.

### Specifying path to Semgrep YAML config

In salus.yaml, you can specify a set of semgrep rules with a path to a [Semgrep config file](https://github.com/returntocorp/semgrep/blob/develop/docs/configuration-files.md).  You **must** specify

* `config` - a full Semgrep config file
* Either `required: true` or `forbidden: true`
  - If a found pattern is forbidden or if a not found pattern is required, then the scanner will fail and the `message` will be show to the developer in the report.

In addition, you can **optionally** specify

* `exclude` - Skip any file or directory that matches this pattern
  - `--exclude='*.py'` will ignore the following: foo.py,
    src/foo.py, foo.py/bar.sh. --exclude='tests' will ignore tests/foo.py as well as a/b/tests/c/foo.py. Can add
    multiple times.

Here is an example semgrep section of a salus.yaml.

```yaml
scanner_configs:
  Semgrep:
    matches:
      - config: semgrep_config_1.yaml
        forbidden: true
      - config: semgrep_config_2.yaml
        forbidden: true
        exclude:
          - tests
```

Example semgrep_config_1.yaml.  The rule says find all patterns of the form
`$X == $X`, but exclude `0 == 0`.
```yaml
rules:
  - id: eqeq-always-true
    patterns:
      - pattern: $X == $X
      - pattern-not: 0 == 0
    message: "$X == $X is always true"
    languages: [python]
    severity: ERROR
```
Keywords in this file:
* `id` - Unique, descriptive identifier, cannot contain whitespaces (required)
* `patterns` or `pattern` - patterns or pattern or pattern-regex (required)
* `message` - Message if rule (forbidden and found) or (required and not found) (optional)
* `languages` - Any of: c, go, java, javascript, or python (required)
* `severity` - One of: WARNING, ERROR (required)


### Adding simple rule directly (without Semgrep config file)

Simple rules that can be expressed with a single `pattern` can be directly specified in salus.yaml.
Each simple rule in salus.yaml **must** include

* `pattern` - the single pattern
* `forbidden: true` or `required: true
* `language`- Any of: c, go, java, javascript, or python
* `sub-dir` - this pattern will apply only to the sub-dir listed. This should be a valid sub-directory under the directory defined by "directories" under "recursion" config

The user can **optionally** provide
* `exclude` - Skip any file or directory that matches this pattern
  - `--exclude='*.py'` will ignore the following: foo.py,
    src/foo.py, foo.py/bar.sh. --exclude='tests' will ignore tests/foo.py as well as a/b/tests/c/foo.py. Can add
    multiple times.
* `message` - Message if rule (forbidden and found) or (required and not found)

Example,

```yaml
scanner_configs:
  Semgrep:
    matches:
      - pattern: $X == $X
        message: Useless equlity check
        language: python
        forbidden: true
        exclude:
          - tests
      - pattern: $X.unsanitize(...)
        message: Don't call `unsanitize()` methods without careful review
        language: js
        forbidden: true
        exclude:
          - node_modules
      - pattern: $LOG_ENDPOINT = os.getenv("LOGGER_ENDPOINT", ...)
        message: All files need to get the dynamic logger. Please don't hardcode this.
        language: python
        required: true
```

## Whitelisting Findings

Please see [semgrep's documentation on how to use an inline comment to allowlist findings](https://semgrep.dev/docs/ignoring-files-folders-code/#reference-summary).

You can also whitelist all findings for specific ids in the salus config, like
```yaml
scanner_configs:
  Semgrep:
    exceptions:
      - advisory_id: myid1
        changed_by: engineer1
        notes: false positive because ...
      - advisory_id: myid2
        changed_by: engineer2
        notes: false positive because ...
```

## Limitations of Semgrep

* There may be parser-related issues from Semgrep
  - Parser-related issues will be displayed as warnings and do not cause salus to fail.
  - Salus will still show semgrep results from files that do not have parser issues.
* Salus semgrep currently does not support scanning against [pre-built rules.](https://github.com/returntocorp/semgrep#run-pre-built-rules)
  - But we plan to support this in the near future!
