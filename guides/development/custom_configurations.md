---
label: Creating Custom Configurations
---
# Setting up custom configs for your scanner
For setting up custom configurations for your scanner, you can optionally use the helper method [```build_options```](https://github.com/coinbase/salus/blob/master/lib/salus/scanners/base.rb#L473).
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

```yaml salus.yaml
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

---