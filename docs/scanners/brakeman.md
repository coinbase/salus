# [Brakeman](http://brakemanscanner.org/)

The [Brakeman Scanner](http://brakemanscanner.org/) is a static analysis tool that finds vulnerabilities in Ruby on Rails projects. It's internal AST and ability to follow data throughout the codebase makes it particularly strong at finding common vulnerabilities such as SQLi, XSS and RCE.

## Configuration

Brakeman's configuration is complex and it parses its own `brakeman.ignore` file. Salus will let Brakeman reuse this file if it's present. To create one, you can use `brakeman -I` which lets you run an interactive scan.
For more information on Brakeman configs, see [Brakeman Options](https://brakemanscanner.org/docs/options/)

## Configuration
```yaml
  scanner_configs:
    Brakeman:
        config: "path/to/config" # Config file for brakeman path, anything in the command line config here will override the brakeman config file. By default it will look for a config in: ./config/brakeman.yml, ~/.brakeman/config.yml, and /etc/brakeman/config.yml. 'Config' is the 'c' brakeman config option.
        all: true # When true, Brakeman runs all checks, off by default. 'All' is the 'A' brakeman config option.
        no-threads: true # By default Brakeman runs each check in a separate thread. When true, disables this behavior. 'No-threads' is the 'n' brakeman config option.
        path: path/to/rails/app # By default, Salus will scan the top level directory, set this if you wish to override this behavior
        no-informational: true # When true, this supppresses informational warnings. 'No-informational' is the 'q' brakeman config option.
        rails3: true # When true, this forces brakeman into rails 3 mode. This should not be necessary if you have a Gemfile.lock file. 'Rails3' is the '3' brakeman config option.
        rails4: true # When true, this forces brakeman into rails 4 mode. This should not be necessary if you have a Gemfile.lock file. 'Rails4' is the '4' brakeman config option.
        no-assume-routes: true # Brakeman used to parse routes.rb and attempt to infer which controller methods are used as actions. However, this is not perfect (especially for Rails 3/4), so now it assumes all controller methods are actions. To disable this behavior set this to true. 
        escape-html: true # This forces Brakeman to assume output is escaped by default. This should not be necessary. 
        faster: true # This will disable some features, but will probably be much faster (currently it is the same as --skip-libs --no-branching). WARNING: This may cause Brakeman to miss some vulnerabilities.
        no-branching: true # To disable flow sensitivity in if expressions set this to true
        branch-limit: 5 # This should be an integer value. 0 is almost the same as --no-branching but --no-branching is preferred. The default value is 5. Lower values generally make Brakeman go faster. -1 is the same as unlimited.
        skip-files: # To skip certain files
            - file1
            - file2
        only-files: # Very dangerous. This only looks at certain files
            - some_file
            - some_dir
        skip-libs: true # To skip processing of the lib/ directory
        test: # To run a subset of checks
            - check1 
            - check2
        except: # To exclude checks
            - check1 
            - check2
        ignore: path/to/config.ignore # Brakeman will ignore warnings if configured to do so. By default, it looks for a configuration file in config/brakeman.ignore. To specify a file to use this argument. 'Ignore' is the 'i' brakeman config option.
        exceptions:
          - advisory_id: e0636b950dd005468b5f9a0426ed50936e136f18477ca983cfc51b79e29f6463
            changed_by: security-team
            notes: Currently no patch exists and determined that this vulnerability is not exploitable.
            expiration: "2021-04-27"
        ignore-model-output: true # To ignore possible XSS from model attributes
        ignore-protected: true # Brakeman will raise warnings on models that use attr_protected. To suppress these warnings, set this to true. 
        report-direct: true # To only raise warnings only when untrusted data is being directly used
        safe-methods:  # To indicate certain methods return properly escaped output and should not be warned about in XSS checks
            - benign_method_escapes_output
            - totally_safe_from_xss
        url-safe-methods:  # Brakeman warns about use of user input in URLs generated with link_to. Since Rails does not provide anyway of making these URLs really safe (e.g. limiting protocols to HTTP(S)), safe methods can be ignored with
            - ensure_safe_protocol_or_something
        warning: # To only get warnings above a given confidence level. The -w switch takes a number from 1 to 3, with 1 being low (all warnings) and 3 being high (only highest confidence warnings). 'Warning' is the 'w' brakeman config option.
```

## Exceptions

The except configuration is supported for backwards compatibility and will be deprecated in the future.  Salus exceptions are being normalized to the new exceptions configuration
