# [Brakeman](http://brakemanscanner.org/)

The [Brakeman Scanner](http://brakemanscanner.org/) is a static analysis tool that finds vulnerabilities in Ruby on Rails projects. It's internal AST and ability to follow data throughout the codebase makes it particularly strong at finding common vulnerabilities such as SQLi, XSS and RCE.

## Configuration

Brakeman's configuration is complex and it parses its own `brakeman.ignore` file. Salus will let Brakeman reuse this file if it's present. To create one, you can use `brakeman -I` which lets you run an interactive scan.

## Configuration
```yaml
  scanner_configs:
    Brakeman:
    - path: path/to/rails/app             # default -  looks for project_root/app
```
