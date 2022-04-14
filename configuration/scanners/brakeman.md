---
icon: dot
tags: [config, scanner]
---
# [Brakeman](http://brakemanscanner.org/)

The [Brakeman Scanner](http://brakemanscanner.org/) is a static analysis tool that finds vulnerabilities in Ruby on Rails projects. It's internal AST and ability to follow data throughout the codebase makes it particularly strong at finding common vulnerabilities such as SQLi, XSS and RCE.

## Configuration

Brakeman's configuration is complex and it parses its own `brakeman.ignore` file. Salus will let Brakeman reuse this file if it's present. To create one, you can use `brakeman -I` which lets you run an interactive scan.
For more information on Brakeman configs, see [Brakeman Options](https://brakemanscanner.org/docs/options/)

The following configuration options are available for Brakeman in Salus

---

### all
=== all
When true, Brakeman runs all checks, off by default. 'All' is the 'A' brakeman config option.

```yml
Brakeman:
	all: true
```
===

---

### config
=== config
Config file for brakeman path, anything in the command line config here will override the brakeman config file. By default it will look for a config in: ./config/brakeman.yml, ~/.brakeman/config.yml, and /etc/brakeman/config.yml. 'Config' is the 'c' brakeman config option.
```yml
scanner_configs:
	Brakeman:
		config: "path/to/config"
```
===

---

### branch-limit
=== branch-limit : `number`
This should be an integer value. 0 is almost the same as --no-branching but --no-branching is preferred. The default value is 5. Lower values generally make Brakeman go faster. -1 is the same as unlimited.
===

---

### escape-html
=== escape-html : `bool`
This forces Brakeman to assume output is escaped by default. This should not be necessary. 
===

---

### except
=== except : `Array`
List of checks to exclude 
```yml
except: 
	- check1 
	- check2
```
===

---

### faster
=== faster `bool`
This will disable some features, but will probably be much faster (currently it is the same as --skip-libs --no-branching). WARNING: This may cause Brakeman to miss some vulnerabilities.
```yml
faster: true
```
===

---

### ignore
=== ignore : `string`
Brakeman will ignore warnings if configured to do so. By default, it looks for a configuration file in config/brakeman.ignore. To specify a file to use this argument. 'Ignore' is the 'i' brakeman config option.

```yml
ignore: path/to/config.ignore
```
===

---

### ignore-model-output
=== ignore-model-output `bool`
To ignore possible XSS from model attributes
===

---

### ignore-protected
=== ignore-protected : `bool`
Brakeman will raise warnings on models that use attr_protected. To suppress these warnings, set this to true. 
===

---


### no-assume-routes
=== no-assume-routes : `bool`
Brakeman used to parse routes.rb and attempt to infer which controller methods are used as actions. However, this is not perfect (especially for Rails 3/4), so now it assumes all controller methods are actions. To disable this behavior set this to true. 
===

---

### no-branching
=== no branching : `bool`
To disable flow sensitivity in if expressions set this to true
===

---

### no-informational
=== no-informational : `bool`
When true, this supppresses informational warnings. 'No-informational' is the 'q' brakeman config option.
===

---

### no-threads
=== no-threads : `bool`
By default Brakeman runs each check in a separate thread. When true, disables this behavior. 'No-threads' is the 'n' brakeman config option.
===

---

### only-files
=== only-files : `Array`
Very dangerous. This only looks at certain files
```yml
only-files: 
  - some_file
  - some_dir
```
===

---

### path
=== path: `string`
By default, Salus will scan the top level directory, set this if you wish to override this behavior
```yml
path: path/to/rails/app 
```
===

---

### report-direct
=== report-direct `bool`
To only raise warnings only when untrusted data is being directly used
===

---
### rails3
=== rails3 : `bool`
When true, this forces brakeman into rails 3 mode. This should not be necessary if you have a Gemfile.lock file. 'Rails3' is the '3' brakeman config option.
===

---

### rails4
=== rails4 : `bool`
When true, this forces brakeman into rails 4 mode. This should not be necessary if you have a Gemfile.lock file. 'Rails4' is the '4' brakeman config option.
===

---

### safe-methods
=== safe-methods : `Array`
To indicate certain methods return properly escaped output and should not be warned about in XSS checks
```yml
safe-methods:
  - benign_method_escapes_output
  - totally_safe_from_xss
```
===

---
### skip-libs
=== skip-libs : `bool`
To skip processing of the lib/ directory
===

---

### skip-files
=== skip-files : `bool`
To skip processing of the lib/ directory
===

---

### test
=== test `Array`
list of checks to run
```yml
test:
	- check1 
	- check2
```
===

---

### url-safe-methods
=== url-safe-methods : `Array`
Brakeman warns about use of user input in URLs generated with link_to. Since Rails does not provide anyway of making these URLs really safe (e.g. limiting protocols to HTTP(S)), safe methods can be ignored with
```yml
url-safe-methods:
  - ensure_safe_protocol_or_something
```
===

---


### warning
=== warning : `number`
To only get warnings above a given confidence level. The -w switch takes a number from 1 to 3, with 1 being low (all warnings) and 3 being high (only highest confidence warnings). 'Warning' is the 'w' brakeman config option.
===

---

## Sample Configuration for Scanner
```yaml
  scanner_configs:
    Brakeman:
        config: "path/to/config" 
        all: true 
        no-threads: true 
        path: path/to/rails/app 
        no-informational: true 
        rails3: true
        rails4: true 
        no-assume-routes: true 
        escape-html: true  
        faster: true 
        no-branching: true 
        branch-limit: 5 
        skip-files: 
            - file1
            - file2
        only-files: 
            - some_file
            - some_dir
        skip-libs: true 
        test:
            - check1 
            - check2
        except:
            - check1 
            - check2
        ignore: path/to/config.ignore 
        exceptions:
          - advisory_id: e0636b950dd005468b5f9a0426ed50936e136f18477ca983cfc51b79e29f6463
            changed_by: security-team
            notes: Currently no patch exists and determined that this vulnerability is not exploitable.
            expiration: "2021-04-27"
        ignore-model-output: true
        ignore-protected: true
        report-direct: true
        safe-methods: 
            - benign_method_escapes_output
            - totally_safe_from_xss
        url-safe-methods: 
            - ensure_safe_protocol_or_something
        warning: 
```