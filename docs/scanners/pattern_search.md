# Pattern Search

This scanner can flag anti-patterns found in a codebase or require that certain strings be present. This might be useful for preventing the use of dangerous methods like `eval()` in Ruby (which might allow for RCE) or `dangerouslySetInnerHTML` in React (which might allow for XSS). By default, all found patterns are added to the info section of the report. If a found pattern is forbidden, this scanner will fail and the `message` will be show to the developer in the report to give additional context on why this was an issue. A `required` pattern must be found in order for the scan to pass.

The tool [sift](https://sift-tool.org), written in Go, is used to perform the pattern matching.

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
        include_extension:
          - js
          - erb
          - html
          - htm
      - regex: "# Threat Model"
        message: All repos must contain a documented threat model.
        required: true
        exclude_extension:
          - rb
          - js
```
