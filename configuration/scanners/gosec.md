---
icon: dot
tags: [config, scanner]
---
# [Gosec](https://github.com/securego/gosec)

The [Gosec Scanner](https://github.com/securego/gosec) is a static analysis tool that finds vulnerabilities in Go projects using the Go AST. Gosec supports Go modules as of Gosec 2.0.0.


## Configuration
In addition to the [global scanner configurations](/configuration/scanners/), the Gosec scanner has specific configurations available. 

The following configuration options are available for the Gosec scanner.

---

### confidence
=== confidence : `string`
This option filters out issues with a lower `confidence` than configured. The valid `string` options are `low`, `medium` or `high`
```yml Filter out the issues with confidence lower than medium
scanner_configs:
  Gosec:
    confidence: medium
```
===

---

### exclude
=== exclude : `Array`
List of rules IDs to exclude, deprecated in favor of [exceptions](/configuration/scanners/#exceptions)
```yml
scanner_configs:
  Gosec:
    exclude:
      - G102
```
===

---

### exclude-dir
=== exclude-dir : `Array`
excludes folders and its contents from scan

```yml
scanner_configs:
  Gosec:
    exclude-dir:
      - tests
      - temp
      - vendor
```
===

---

### include
=== include : `Array`
List of rules IDs to include
!!!
only basic regex formatting is performed and does not check if this is the assigned value is a valid rule number
!!!
```yml
scanner_configs:
  Gosec:
    include:
      - G104
      - G105
```
===

---

### no-fail
=== no-fail : `bool`
This option determines if the scanner should fail if issues were found.  

```yml Do not fail the scan, even if issues were found
scanner_configs:
  Gosec:
    no-fail: false
```
===

---

### nosec
=== nosec : `bool`
Ignores #nosec comments when set to true. This is the default functionality in Salus
```yml
scanner_configs:
  Gosec:
    nosec: false
```
===

---

### nosec-tag
=== nosec-tag : `string`
Set an alternative string for #nosec (default)
```yml
nosec-tag: falsepositive 
```
===

---

### run_from_dirs
=== run_from_dirs : `Array`
run gosec from the specified subdirs only. for now, any other gosec config will apply to all subdir runs
```yml
scanner_configs:
  Gosec:
    run_from_dirs:
      - subdir1
      - subdir2
```
===

---

### 
=== severity : `string`
This option filters out issues with a lower severity than configured. It can take the `string` options `low`, `medium` or `high`
```yml Filter out the issues with severities lower than medium
scanner_configs:
  Gosec:
    severity: medium
```
===

---
### 
=== sort : `bool`
This option determines if issues should be sorted by severity
```yml Do not sort issues by severity
scanner_configs:
  Gosec:
    sort: false
```
===

---
### tests
=== tests : `bool`
This option determines if tests files should be scanned
```yml 
scanner_configs:
  Gosec:
    tests: false 
```
===

---
## Sample Configuration
```yaml
  scanner_configs:
    Gosec:
    - nosec: false
      nosec-tag: falsepositive
      include: 
        - G104
      exclude:                            
        - G102
      sort: true
      severity: low
      confidence: low
      no-fail: false
      tests: false 
      exclude-dir:                       
        - tests
        - temp
        - vendor
      run_from_dirs:                     
        - subdir1                        
        - subdir2
      exceptions:
        - advisory_id: G101
          changed_by: security-team
          notes: Currently no patch exists and determined that this vulnerability is not exploitable.
          expiration: "2021-04-27"
```
!!!
The **exclude** configuration is supported for backwards compatibility and will be deprecated in the future.  Please use [exceptions](/configuration/scanners/#exceptions) instead 
!!!