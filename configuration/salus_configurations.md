---
icon: tools
label: Salus Configuration
order: 100
---
---
## Providing Configuration to Salus

Salus supports multiple methods of parsing config files. 

### Overriding the Default Configuration
Salus uses a [default configuration](https://github.com/coinbase/salus/blob/master/salus-default.yaml) if no other configuration is provided. This helps prevent misconfigurations that might result in silent failures.

The easiest way to provide custom configuration to Salus is to put a `salus.yaml` file in the root of the project that is being scanned. This will automatically be read by Salus and any configurations given will overwrite the default configurations. 

Running the command below will use your salus config file (`salus.yaml`) if it is present
```sh
docker run --rm -v $(pwd):/home/repo coinbase/salus
```
!!!
To override the default configuration make sure your config file is named `salus.yaml` and not `salus.yml`
!!!

---

### Using a Local Configuration File
If you have a configuration file in the root in a different folder within the Project, you can point to it with the `--config` flag (or `-c`). For example, if you had the configuration file at the location `./tests/salus-config.yaml` you can use the following command.

```sh Running Salus with a Config file located in the tests folder
docker run --rm -v $(pwd):/home/repo coinbase/salus --config file://tests/salus-config.yaml
```

```sh Running Salus with a Config file located in the root directory
docker run --rm -v $(pwd):/home/repo coinbase/salus --config file://salus-config.yaml
```

---

### Using a Remote Configuration File
Salus also supports remote configuration files that can be fetched over HTTP. This is particularly useful for organization-wide configurations that are centralized.

```sh Running Salus with a Config File located at a URL 
docker run --rm -v $(pwd):/home/repo coinbase/salus --config https://salus-config.internal.net/salus.yaml
```

---


### Using Multiple Configuration Files (Cascading Configurations)
You can append multiple configuration files by listing the configuration URIs in order of ascending precedence. 

Salus merges the `Hash` in the configuration files and the keys are preserved but values are overwritten. A space (`" "`) is used to delimit each configuration file.

```sh Running Salus with 2 Config Files
docker run --rm -v $(pwd):/home/repo coinbase/salus --config \
"file://tests/salus-config.yaml file://local-salus-config.yaml"
```

When using a global configuration provided over HTTP, you might still want to modify Salus for special cases relevant only to the scanned repository. 

```sh Running Salus with 2 Config Files
docker run --rm -v $(pwd):/home/repo coinbase/salus --config \
"https://salus-config.internal.net/global.yaml file://local-salus-config.yaml"
```

!!!
Wrap multiple configuration files with quotes " "
!!!

---

### Using `SALUS_CONFIGURATION`
A third method of providing configuration URIs is via the environment variable `SALUS_CONFIGURATION`. If this envar is set, it will take precedence over the flag URI.

---

## Salus Configurations Options

Each configuration file should be valid YAML and may contain the following values.

### active_scanners
=== active_scanners : `Array` or `String`
Lists which scanners should run. These scanners are only triggered if they are relevant to the project. 
```yml
active_scanners:
  - PatternSearch
  - Brakeman
  - BundleAudit
  - NPMAudit
```
String value of "all" or "none" which are placeholders for the config to use all Salus Scanners or none of them.
```yml No Scanner set as an active scanner
active_scanners: none
```

All Salus Scanners are set as active scanners. Each scanner will execute if the source code requires that scanner
```yml All Salus Scanners are set as active scanners
active_scanners: all
```
===

---

### builds
=== builds : `Hash`
Hash with build info. This config option can contain arbitrary keys.

```yml
builds:
  url: "{{BUILD_URL}}"   # See Envar Interpolation section
  service_name: circle_ci
```
=== 

### cascade_config
Cascade_config contains available settings to control how multiple configuration files are cascaded

!!!
Put this configuration in the config file with the highest precedence
!!!

=== combine_arrays `bool`
When cascading configurations this option determines if arrays values for the same key should be combined. 

Having this option set to false would use the array `values` in the config file with the highest precedence when multiple config files configure the same option.

When this option is true, the `values` for conflicting options will be merged

For example if you had two configuration files
```yml salus-config1.yml
active_scanners:
  - Semgrep
```

```yml salus-config2.yml
active_scanners:
  - BundleAudit
  - NPMAudit
```

Running Salus with the command
```sh salus-config1.yml has a higher precedence than salus-config2.yml
docker run --rm -v $(pwd):/home/repo coinbase/salus --config \
"file://salus-config2.yaml file://salus-config1.yaml"
```
The configurations for `active_scanner` in `salus-config1.yml` would override the configurations for `active_scanners` in `salus-config2.yml`

The following sample shows how to configure this option
```yml Array Values for conflicting keys will be merged
cascade_config:
  combine_arrays: true
```

===

---

### custom_info
=== custom_info : `Any YAML Type`
Used in the report for any additional information that the consumer of the [Salus Report](/salus_reports) might use. 

```yml
custom_info: "PR-123"
```

The user can define what values are stored here. The Information listed in here shows up in the exported [Salus Report](/salus_reports)

```yml User Defined Keys
custom_info:
  field1: 1
  field2: 
    - field: Hello
```
```json JSON output in salus report
"custom_info": {
    "field1": 1,
    "field2": [
      {
        "field": "Hello"
      }
    ]
  },
```

===

---

### enforced_scanners
=== enforced_scanners: `Array` or `String`
enforced_scanners are scanners that cause Salus to fail if the scanner fails. Controlling this list will allow you to choose which scanners must pass for a CI environment to show a successful build. It can allow you to run new scanners in test mode while being tuned or rolled out across a fleet of builds.

By default, Salus enforces all scanners which we deem to have low false positive rates. Strong defaults lower the risk of misconfiguration that could fail closed if the configuration was necessary to ensure certain scanners pass. Other scanners may need to graduate from the testing phase or should only be enforced explicitly by custom configuration.

The following sample shows how to configure this option
```yml
enforced_scanners:
  - PatternSearch
  - Brakeman
```
===

---

### project_name
=== project_name : `String`
Used in the report to identify the project being scanned.

```yml
project_name: "my-repo"
```
===

---

### reports
`reports` : `Array`

Each entry in reports must contain keys for `uri` and `format`. This help define where to send Salus reports and in what format.

!!!
Values specified with two parentheses i.e **{{** VALUE **}}** will be treated as an environment variable `ENV[VALUE]` while values
specified without will be set as is. 
!!!
=== uri : `string`
Defines where to send Salus reports. This is a required configuration for the `reports` option

The value can point to either the local file system or remote HTTP destinations.
```yml Salus Report is sent to a remote destination
reports: 
  - uri: https://salus-config.internal2.net/salus-report
    format: json
```

```yml Salus Report is sent to a local file at ./result.json
reports:
  - uri: file://result.json
    format: json
```

```yml Salus Report is sent to multiple destinations
reports:
  - uri: file://result.json
    format: json
  - uri: https://salus-config.internal2.net/salus-report
    format: json
```

===
---

=== format : `string`
This option defines what format to export salus reports. This is a required configuration for the `reports` option
The available formats are:
- `json`
- `yaml`
- `txt`
- `sarif`
- `cyclonedx-json`

===
---

=== verbose : `bool`

is an optional key and defaults to false.

===
---

=== post : `Hash`
Each report hash can add post parameters using the `post` option

Options | Description
--- | ---
`salus_report_param_name` | Salus reports can be sent as a report parameter by specifying the parameter name in `salus_report_param_name`. when this is not defined, the salus report will be located in the body of the request sent
`additional_params` | additional post parameters can be specified through the `additional_params` field

This Example shows how to configure this option
```yml 
reports:
  - uri: https://salus-config.internal2.net/salus-report
    format: json
    verbose: true
    post:
      salus_report_param_name: 'report'
      additional_params:
        repo: 'Random Repo'
        user: 'John Doe' 
```
===
---

=== put : `string`
Each report hash can also specify what http verb should be used. Salus currently supports `put` and `post`. If `puts` is not defined, Salus defaults to use `post`

===

---

=== headers : `Array`
you can pass in `headers` with the corresponding `key` and `value` pairs list.
```yml
reports:
  - uri: https://salus-config.internal2.net/salus-report
    format: sarif
    put:
    headers:
      Age: '12'
      X-API-Key: '{{RANDOM_API_KEY}}'
```
===

---

=== cyclonedx_options : `Hash`
Additional options are also available for cyclonedx using the optional keyword `cyclonedx_options`

Options | Description
--- | ---
`cyclonedx_project_name`  | This option allows users to specify the cyclonedx report project name.
`spec_version`  | This option allows users to specify the cyclonedx report spec version. Currently, only versions 1.2 and 1.3 are supported, with 1.3 being the default version if the parameter is not specified.

```yml 
reports:
  - uri: https://salus-config.internal2.net/salus-report
    format: cyclonedx-json
    put:
    headers:
      Age: '12'
      X-API-Key: ''
    cyclonedx_options:
      cyclonedx_project_name: '/'
      spec_version: '1.3'
```
===

---

=== sarif_options : `Hash`
Additional options are also available for sarif using the optional `sarif_options` config

Options | Description
--- | ---
`include_suppressed` | This  `boolean` option allows users to include/exclude suppressed/excluded results in their sarif reports. Currently, this is supported for NPM audit reports

```yml
reports:
  - uri: https://salus-config.internal2.net/salus-report
    format: json
    verbose: true
    post:
      salus_report_param_name: 'report'
      additional_params:
        repo: 'Random Repo'
        user: 'John Doe' 
  - uri: file://tests/salus-report.sarif
    format: sarif
    sarif_options:
      include_suppressed: true
```
===

---

### scanner_configs
=== scanner_configs `Hash`
Defines configuration relevant to specific scanners.

```yml
scanner_configs:
  BundleAudit:
    ignore:
      - CVE-XXXX-YYYY
  YarnAudit:
    exceptions:
      - advisory_id: "CVE-2020-2020"
        changed_by: security-team
        notes: Currently no patch exists and determined that this vulnerability is not exploitable.
```
!!!
Special configurations that exists for particular scanners is defined in the [scanners directory](/configuration/scanners).
!!!

===




## Envar Interpolation

It's sometimes useful, especially in CI clusters, to have a generalized configuration file to reference environment variables. Salus will interpolate the configuration files before parsing them. To reference an environment variable, put the name of the envar in two parentheses, **{{** ENVAR_NAME **}}**.

```yaml
project_name: "{{GITHUB_ORG}}-{{GITHUB_REPO}}-{{COMMIT_SHA}}"
```
