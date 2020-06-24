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

#### Speciying path to Semgrep YAML config

In salus.yaml, you can specify a semgrep rule with a path to a [Semgrep config file](https://github.com/returntocorp/semgrep/blob/develop/docs/configuration-files.md).  You **must** specify

* `config` - a full Semgrep config file
* Either `required: true` or `forbidden: true`
** If a found pattern is forbidden, this scanner will fail and the `message` will be show to the developer in the report. A `required` pattern must be found in order for the scan to pass.

In addition, you can **optionally** specify

* `exclude_directory` - directory to exclude from scanning
** The glob pattern will match anywhere in the file path parts so for example `exclude_drectory: [node_modules]` will ignore both `./node_modules`, `lib/node_modules`, and `demo/demo2/node_modules`. Passing in full paths such as `exclude_drectory: [lib/node_modules]` is not supported.

Here is an example semgrep section of a salus.yaml.  Each match represents a rule.

```yaml
scanner_configs:
  Semgrep:
    matches:
      - config: semgrep_config_1.yaml
        required: true
      - config: semgrep_config_2.yaml
        forbidden: true
        exclude_directory:
          - tests
```

Example semgrep config file
```yaml
# semgrep_config_1.yaml
rules:
  - id: eqeq-always-true                  # Unique, descriptive identifier (required)
    patterns:                             # patterns or pattern or pattern-regex (required)
      - pattern: $X == $X
      - pattern-not: 0 == 0
    message: "$X == $X is always true"    # Message if rule (forbidden and found) (optional)
                                                         or (required and not found)
    languages: [python]                   # Any of: c, go, java, javascript, or python (required)
    severity: ERROR                       # One of: WARNING, ERROR (required)
```

#### Adding simple rule directly (without Semgrep config file)

Simple rules that can be expressed with a single `pattern` can be directly specified in salus.yaml.
Each simple rule **must** include

* `pattern` - the single pattern
* `forbidden: true` or `required: true
* `language`- Any of: c, go, java, javascript, or python

The user can **optionally** provide
* `exclude_directory` - directory to exclude from scanning
** The glob pattern will match anywhere in the file path parts so for example `exclude_drectory: [node_modules]` will ignore both `./node_modules`, `lib/node_modules`, and `demo/demo2/node_modules`. Passing in full paths such as `exclude_drectory: [lib/node_modules]` is not supported.
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
      - config: semgrep_config.yml
        required: true
```

## Limitations of Semgrep

* There may be parser-related issues from Semgrep
** Parser-realted issues are will be displayed as warnings and will not cause salus to fail.
** Salus will still show semgrep results on files that do not have parser issues.
* Salus semgrep currently does not support scanning against [pre-built rules.](https://github.com/returntocorp/semgrep#run-pre-built-rules)
** But we plan to support this in the near future!
