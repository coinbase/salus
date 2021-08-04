# `Salus::Scanners::Base`

The parent class of all scanners. Contains methods useful for executing scanners and reporting results.

## Config global to all scanners

#### Pass on Raise

Some scanners are very resilient and it's rare for them to throw exceptions. Usually this is for good reason, like a malformed file is unparsable by the scanner and so this warrants breaking the project's build. By default, if a scanner raises an exception for whatever reason, then the scanner is conidered _failed_ as if it found an actual security issue.

However, some scanner fail frequently for reasons out of the developer's control. For example, a CVE registry might be down which means that a CVE scanner cannot update it's local DB and this causes it to raise an error. In that scenario, you might decide that Salus's overall status, and therefore the CI/CD pipeline should not fail. To allow for a scanner to be considered a _pass_ when it raises an exception, you can provide the value `true` for the directive `pass_on_raise`. For example:

```yaml
scanner_configs:
  YarnAudit:
    pass_on_raise: true
```

When this is set to `true`, any errors thrown by the scanner will still be recorded in the report.

#### Custom Failure Messages

You can define a custom message to be shown to the developer when the given scanner fails. This is useful for pointing developers to internal security resources or teams that can help address the failure.

Example with `BundleAudit` configuration:

```yaml
scanner_configs:
  BundleAudit:
    failure_message: |
      A CVE was found in one of your gems. Please try to upgrade the offending gem.
        $ bundle update <gem name>

      If this does not resolve the error, seek advice from the security team.
      Slack channel: #security
```

#### Maximum Lifespan

At times, scanners may perform scans for unacceptable lengths of time. To limit this behavior, you can define `scanner_timeout_s` with the number of seconds you wish the scan to last before it times out.  

Example with `YarnAudit` configuration:

```yaml
scanner_configs:
  YarnAudit:
    scanner_timeout_s: 60
```

This will limit YarnAudit scans to 1 minute (60 seconds) in execution time.

## Reading/setting up custom configs for your scanner

For setting up custom configurations for your scanner, you can optionally use the helper method ```build_options```.
You do not have to use this method if it doesn't help you use your scanner. 

For example, let's pretend you intend to send in the configurations in the following format:

```-flag -string=foo --list=foo,bar,baz -bool=true -file=./foobar.js -file_list=foo.js,bar.js -multiple first -multiple second -d```

Note each type for the arguments, the supported types are:
```ruby
  :flag
  :string # Numbers qualify as strings
  :list # For a list of strings
  :bool
  :file 
  :file_list # For a list of files
```

You would call build options like so:

```ruby 
build_options(
  prefix: '-', # The default item meaning a new argument
  suffix: ' ', # The way arguments are separated
  separator: '=', # The item that separates the argument's name and value
  # join_by: ',', # Optional argument to denote items in a list, is set to ',' by default
  args: { # The actual list of arguments
    flag: :flag, # Set the type for flags as ':flag'
    string: :string, 
    # string: /^foo$/, # Optionally, you can set a regex to the value, and then it will automatically know it is a string
    list: { # For cases where it doesn't use the defaults, you can set an argument with a hash like:
      type: :list, # Always set a type
      prefix: '--', # Override the default prefix
      # regex: /\Afoo|bar|baz\z/i, # Optionally you can use a regex to only allow certain matches
    },
    file: :file,
    file_list: :file_list,
    multiple: :string,
    descriptive: { # Use a more descriptive name
      type: :flag,
      keyword: 'd' # Use the original non-descriptive name here
    }
  }
)
```

This will automatically format and read the yaml config file for the scanner configs:

```yaml
scanner_configs:
  MyScanner:
    flag: true # Flags are set as true/false if they exist, similar to booleans
    string: 'foo'
    list: 
      - 'foo'
      - 'bar'
      - 'baz'
    bool: true
    file: './foobar.js'
    file_list: # file and file list will validate if the file exists before continuing
      - 'foo.js'
      - 'bar.js'
    multiple: # For a parameter that appears multiple times, just make it a list. Lists of lists are not supported
      - 'first'
      - 'second'
    descriptive: true # Use your descriptive name in the yaml config
```