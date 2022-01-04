# Pattern Search

PatternSearch uses [sift](https://sift-tool.org), written in Go, to perform the pattern matching.

This scanner can flag anti-patterns found in a codebase or require that certain strings be present. This might be useful for preventing the use of dangerous methods like `eval()` in Ruby (which might allow for RCE) or `dangerouslySetInnerHTML` in React (which might allow for XSS). By default, all found patterns are added to the info section of the report. If a found pattern is forbidden, this scanner will fail and the `message` will be show to the developer in the report to give additional context on why this was an issue. A `required` pattern must be found in order for the scan to pass.

The scanner also allows the options below.  These options can be set globally and per-match.  In addition, the `exclude_` options can be used together.

* `exclude_extension` and `include_extension` for excluding and including file extensions, respectively. While these options can be combined, exclusions take precedence when extensions conflict (are both included and excluded) in declarations.
* `exclude_directory` for excluding directories whose name matches GLOB.  It appears that sift does not support `/`s in the directory name.
* `exclude_filepaths` for excluding file paths. Note the file paths must be regular paths, not GLOB, and cannot include regular expressions.
* `not_followed_within` for only showing matches not followed by PATTERN within NUM lines. The value must have the format `NUM:PATTERN`. Use 0 for excluding on the same line.
* `files` for search only files whose name matches GLOB.

## Configuration

```yaml
scanner_configs:
  PatternSearch:
    matches:
      - regex: dangerouslySetInnerHTML
        message: Do not use dangerouslySetInnerHTML to render user controlled input.
        forbidden: true
        exclude_directory:
          - node_modules
        exclude_filepaths:
          - file1.rb
          - subdir/file1.rb
        include_extension:
          - js
          - erb
          - html
          - htm
        not_followed_within: 0:my_pattern
        files:
          - a.js
          - b.js
      - regex: "# Threat Model"
        message: All repos must contain a documented threat model.
        required: true
        exclude_extension:
          - rb
          - js
```
