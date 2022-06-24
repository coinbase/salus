
## Overview
Salus is a tool for coordinating the execution of security Scanners. Salus supports multiple scanners like Bandit, Brankeman, Semgrep, however as new programming languages get introduced, there is always a need to add new scanners to Salus.

This document describes the steps needed to add a new Scanner to Salus

## Steps
This section describes high-level check-list style steps for adding a programming language specific security scanner to Salus

- Make sure to evaluate various scanners available for scanning security vulnerabilities for a programming language 
- If your scanner will use any open source libraries or projects please review the open source software policy.  
- Updating Dockerfile for installing the scanner. Sample Pull request: https://github.com/coinbase/salus/pull/623/files#
- Add/Update Documentation: Make sure to update the README.MD file and also add a scanner specific documentation in https://github.com/coinbase/salus/tree/master/docs/scanners
  - Update lib/salus/repo.rb with the IMPORTANT files we look for in the repo to enable a particular scanner
- Add scanner to lib/salus/scanners sample PR https://github.com/coinbase/salus/pull/623/files#
  - Make sure to provide scanned_languages and scanner_type
- Add Unit-tests, sample PR https://github.com/coinbase/salus/pull/623/files#
- Ensure SARIF report generation logic is added
- Write up a Test plan and furnish details with the test plan run results in the Pull Request to help speed up merging process
- Make scanner configurable, for example "filter-paths" to ignore mocks/tests, exclude-informational, exclude-optimization to reduce noise or false positives
  - All normalized exceptions must be implemented
- Support adding vulnerability exceptions for the scanner in salus.yaml file
- Update salus.yaml on the repos for enabling scanner as an active-scanner

## References
- Slither scanner support Pull Request: https://github.com/coinbase/salus/pull/623/files#
  - Note: Slither is not compatible with Salus License, hence it has been removed from Salus