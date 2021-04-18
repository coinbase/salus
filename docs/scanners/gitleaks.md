# [Gitleaks](https://github.com/zricethezav/gitleaks)

The [Gitleaks Scanner](https://github.com/zricethezav/gitleaks) tool for finding secrets within a directory or Git repo.

## Configuration

Gitleaks currently always runs with the `--recursive` and `--format json` options turned on.
In addition, you can configure the additional options below.
For more information on Gitleaks configuration, see the docs [here](https://github.com/zricethezav/gitleaks#usage-and-options)

```yaml
  scanner_configs:
    Gitleaks:
      config-path: "./gitleaks.conf"
      repo-config-path: "./gitleaks.conf"
      threads: 1
      unstaged: true
      branch: "main"
      redact: true
      no-git: true
      files-at-commit: "aaaaaaaaaaa"
      commit: "aaaaaaaaaaa"
      commits:
      - "aaaaaaaaaaa"
      - "aaaaaaaaaaa"
      commits-file: "./commits.txt"
      commit-from: "aaaaaaaaaaa"
      commit-to: "aaaaaaaaaaa"
      commit-since: "2020-01-01T00:00:00-0000"
      commit-until: "2020-01-01T00:00:00-0000"
      depth: 1
```

The following Gitleaks config options are currently NOT supported.
```yaml
  -r, --repo-url=         Repository URL
  -p, --path=             Path to directory (repo if contains .git) or file
      --username=         Username for git repo
      --password=         Password for git repo
      --access-token=     Access token for git repo
      --ssh-key=          Path to ssh key used for auth
      --debug             Log debug messages
```
