# Trufflehog

Finds leaked secrets

## Configuration

The following config options are available.

```yaml
scanner_configs:
  Trufflehog:
    exclude_files: # List of file paths to ignore
      - env.json 
    only-verified: false  # Only output verified results.
                          # true by default
    exceptions:  # whitelist finding
      - advisory_id: FlatIO-PLAIN
        changed_by: security-team
        notes: My notes.
        expiration: 2022-12-31
```
