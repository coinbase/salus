# CircleCI Orb for Salus

## Parameters

| attribute | description | default | options |
| --------- | ----------- | ------- | ------- |
| salus_executor | CircleCI executor to use that specifies Salus environment | `coinbase/salus:latest` | See [executor reference](https://circleci.com/docs/2.0/configuration-reference/#executors-requires-version-21)|
| active_scanners | Scanners to run | all | Brakeman, PatternSearch, BundleAudit, NPMAudit |
| enforced_scanners | Scanners that block builds | all | Brakeman, PatternSearch, BundleAudit, NPMAudit |
| report_uri | Where to send Salus reports | file://../salus-report.json | Any URI |
| report_format | What format to use for report | json | json, yaml, txt |
| report_verbosity | Whether to enable a verbose report | true | true, false |
| configuration_file | Location of config file in repo (overrides all other parameters except salus_executor) | "" | Any filename |

Note: active_scanners and enforced_scanners must be yaml formatted for Salus configuration file.

## CircleCI Environment Variables

Stored in `custom_info` of a Salus scan.

| Key | CircleCI Variable | Description |
| --- | ----------------- | ----------- |
| sha1    | CIRCLE_SHA1 | Hash of last commit in build |
| ci_project_username | CIRCLE_PROJECT_USERNAME | SCM username of project |
| reponame | CIRCLE_PROJECT_REPONAME | Name of repository |
| branch | CIRCLE_BRANCH | Name of git branch being built |
| tag | CIRCLE_TAG | Name of tag |
| repository_url | CIRCLE_REPOSITORY_URL | URL of the Github or Bitbucket repository |
| compare_url | CIRCLE_COMPARE_URL | URL to compare commits in build |
| build_url | CIRCLE_BUILD_URL | URL for the build |
| external_build_id | CIRCLE_BUILD_NUM | CircleCI or other build identifier |
| pull_requests | CIRCLE_PULL_REQUESTS | Comma-separated list of pull requests |
| ci_username | CIRCLE_USERNAME | SCM username of user who triggered build |
| pr_username | CIRCLE_PR_USERNAME | SCM username of user who created pull/merge request |
| pr_reponame | CIRCLE_PR_REPONAME | Name of repository where pull/merge request was created |
| pr_number | CIRCLE_PR_NUMBER | Number of the pull/merge request |

## Examples

`.circleci/config.yml`

### blocking scan with all scanners

```
version: 2.1

orbs:
  salus: federacy/salus@3.0.0

workflows:
  main:
    jobs:
      - salus/scan
```

### non-blocking scan with all scanners

```
version: 2.1

orbs:
  salus: federacy/salus@3.0.0

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
  salus: federacy/salus@3.0.0

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
  salus: federacy/salus@3.0.0
executors:
  salus_2_4_2:
    docker:
      - image: coinbase/salus:2.4.2
workflows:
  salus_scan:
    jobs: 
      - salus/scan:
          salus_executor:
            name: salus_2_4_2
```

## Unused CircleCI Environment Variables

CI, CI_PULL_REQUEST, CI_PULL_REQUESTS, CIRCLE_INTERNAL_TASK_DATA, CIRCLE_JOB, CIRCLE_NODE_INDEX, CIRCLE_NODE_TOTAL, CIRCLE_PREVIOUS_BUILD_NUM, CIRCLE_PULL_REQUEST, CIRCLE_WORKFLOW_ID, CIRCLE_WORKING_DIRECTORY, CIRCLECI, HOME

