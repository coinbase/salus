# CircleCI Orb for Salus

## Parameters

| attribute | description | default | options |
| --------- | ----------- | ------- | ------- |
| salus_executor | CircleCI executor to use that specifies Salus environment | `coinbase/salus:2.4.2` | See [executor reference](https://circleci.com/docs/2.0/configuration-reference/#executors-requires-version-21)|
| active_scanners | Scanners to run | all | Brakeman, PatternSearch, BundleAudit, NPMAudit |
| enforced_scanners | Scanners that block builds | all | Brakeman, PatternSearch, BundleAudit, NPMAudit |
| report_uri | Where to send Salus reports | file://../salus-report.json | Any URI |
| report_format | What format to use for report | json | json, yaml, txt |
| report_verbosity | Whether to enable a verbose report | true | true, false |
| configuration_file | Location of config file in repo (overrides all other parameters except salus_executor) | "" | Any filename |

Note: active_scanners and enforced_scanners must be yaml formatted for Salus configuration file.

## Examples

.circleci/config.yml

### blocking scan with all scanners

```
version: 2.1

orbs:
  salus: federacy/salus@2.4.2

workflows:
  main:
    jobs:
      - salus/scan
```

### non-blocking scan with all scanners

```
version: 2.1

orbs:
  salus: federacy/salus@2.4.2

workflows:
  main:
    jobs:
      - salus/scan:
          enforced_scanners: "none"
```

### blocking scan with only Brakeman

```
version: 2.1

orbs:
  salus: federacy/salus@2.4.2

workflows:
  main:
    jobs:
      - salus/scan:
          active_scanners: "\n    - Brakeman"
          enforced_scanners: "\n    - Brakeman"
```

### scan with custom Salus executor

```
version: 2.1
orbs:
  salus: federacy/salus@2.4.2
executors:
  salus_latest:
    docker:
      - image: coinbase/salus:latest
workflows:
  salus_scan:
    jobs: 
      - salus/scan:
          salus_executor:
            name: salus_latest
```
