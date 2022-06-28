
## Overview
Salus is a tool for coordinating the execution of security Scanners. Salus supports multiple scanners like [Bandit](https://github.com/coinbase/salus/blob/master/docs/scanners/bandit.md), [Brakeman](https://github.com/coinbase/salus/blob/master/docs/scanners/brakeman.md), [Semgrep](https://github.com/coinbase/salus/blob/master/docs/scanners/semgrep.md), etc, however as new programming languages get introduced there is always a need to add new scanners to Salus.

This document describes the steps needed to add a new Scanner to Salus

## Steps
This section describes high-level check-list style steps for adding a programming language specific security scanner to Salus

#### Pre Check
- Evaluate various scanners available for scanning security vulnerabilities for a programming language and select the best one to integrate. This allows us to have a single high quality scanner compared to multiple low quality scanners.
- Please review the LICENSE specified by the scanner or open source libraries or projects that will be included. Libraries with permissive [LICENSE](https://github.com/PyCQA/bandit/blob/main/LICENSE) such as Apache License 2.0 can be included while libraries with restrictive LICENSE cannot be included.
 

#### Implementation
- Update [Dockerfile](https://github.com/coinbase/salus/blob/master/Dockerfile) to install any dependencies that are required to run the scanner. Sample [PR](https://github.com/coinbase/salus/pull/563).
- Implement the scanner by adding a new class to ``lib/salus/scanners/``. Use [CargoAudit](https://github.com/coinbase/salus/blob/master/lib/salus/scanners/cargo_audit.rb) implementation for reference. 
  - [run](https://github.com/coinbase/salus/blob/d26ff27a442fad594b016837435d4bdcfab42a61/lib/salus/scanners/cargo_audit.rb#L22) function implements the core logic of the scanner.
  - [should_run?](https://github.com/coinbase/salus/blob/d26ff27a442fad594b016837435d4bdcfab42a61/lib/salus/scanners/cargo_audit.rb#L14) function implements logic of when to run a scanner. Update [lib/salus/repo.rb](https://github.com/coinbase/salus/blob/d26ff27a442fad594b016837435d4bdcfab42a61/lib/salus/repo.rb#L7) with the IMPORTANT files we look for.
  - We also want to implement certain functions such as [supported_languages](https://github.com/coinbase/salus/blob/d26ff27a442fad594b016837435d4bdcfab42a61/lib/salus/scanners/cargo_audit.rb#L70) and [scanner_type](https://github.com/coinbase/salus/blob/d26ff27a442fad594b016837435d4bdcfab42a61/lib/salus/scanners/cargo_audit.rb#L18) to be in spec.
  - For more information, refer [CUSTOM SALUS](https://github.com/coinbase/salus/blob/master/docs/custom_salus.md).
- Implement configuration options for Salus scanner that are exposed by the underlying scanner. We aim for the Salus scanner to be non-opinionated as this allows the end users to override and implement their own configs. Use [NPMAudit](https://github.com/coinbase/salus/blob/d26ff27a442fad594b016837435d4bdcfab42a61/lib/salus/scanners/npm_audit.rb#L32) for reference. 
- Implement Exception logic to allow users to exclude certain findings. 
  - ``fetch_exception_ids`` built in function will return the list of ids specified in salus.yaml.
  - Use [Bandit](https://github.com/coinbase/salus/blob/d26ff27a442fad594b016837435d4bdcfab42a61/lib/salus/scanners/cargo_audit.rb#L111) for reference.
- Add [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.pdf) report generation logic as this allows us to combine results from different scanners in a standardized format. Sample [implementation](https://github.com/coinbase/salus/blob/master/lib/sarif/osv/base_sarif.rb) for reference. 
- Implement unit tests for the scanner implemented. Sample [test case](https://github.com/coinbase/salus/blob/master/spec/lib/salus/scanners/bandit_spec.rb) implementation.

#### Documentation
- Add/Update Documentation: Make sure to add a scanner specific documentation in ``salus/docs/scanners``. Sample [GoOSV](https://github.com/coinbase/salus/blob/master/docs/scanners/go_osv.md) documentation. 

## References
- GradleOSV scanner support Pull Request: https://github.com/coinbase/salus/pull/563