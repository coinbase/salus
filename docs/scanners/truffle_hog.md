# Trufflehog

Finds leaked secrets

## Configuration

The following config options are available.

```yaml
scanner_configs:
  Trufflehog:
    exclude:
      - filename1.txt
      - filename2.txt
    only-verified: false  # Only output verified results.
                          # true by default
    exceptions:  # whitelist finding
      - advisory_id: FlatIO-PLAIN
        changed_by: security-team
        notes: My notes.
        expiration: 2022-12-31
```
