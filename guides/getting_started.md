---
icon: rocket
order: 102
---
## Installation
Docker is required to run Salus. The dependencies for the project are stored on a docker, which helps reduce the number of steps necessary to run Salus. 

Docker is available on different operating systems. You can install the appropriate version for your operating system on the [Docker website](https://docs.docker.com/desktop/mac/install/)
+++ Mac

[Docker website](https://docs.docker.com/desktop/mac/install/)

``` Installing Docker with Homebrew
brew install docker
```
+++Windows
[Install Docker for Windows](https://docs.docker.com/desktop/windows/install/)


+++ Linux

[Install Docker for Linux](https://docs.docker.com/engine/install/)
+++


All Set! you are now ready to run Salus :sparkles:


---

## Running Salus
Navigate to the root directory of the project you want to run Salus on
```sh
cd /path/to/repo
```
Run the following line in the root directory (No edits necessary). This will run the latest Version of Salus.
```sh 
docker run --rm -t -v $(pwd):/home/repo coinbase/Salus
```

Running specific versions of Salus is also possible. All you need to do is provide the version tag
```sh Running Salus Version 2.17.6
docker run --rm -t -v $(pwd):/home/repo coinbase/Salus:2.17.6
```

To view all versions of Salus, visit the [releases page](https://github.com/coinbase/Salus/releases)

---

## Configuring Salus
Salus can be configured by providing a salus configuration file 

```sh Running Salus with a main.yaml config file
docker run --rm -t -v $(pwd):/home/repo coinbase/Salus --config main.yaml
```

```yml main.yaml
reports:
  - uri: file://tests/salus-report.txt
    format: txt
  - uri: https://salus-config.internal.net/salus-report
    format: json
    verbose: true
enforced_scanners:
  - PatternSearch
  - Brakeman

active_scanners:
  - PatternSearch
  - Brakeman
  - BundleAudit
  - NPMAudit
```

!!! Note
Salus has different configuration options, visit the [salus configurations page](http://localhost:5000/salus/configuration/salus_configurations/) to learn more about them
!!!

---

## Configuring Salus Scanners

Salus provides [global configurations](http://localhost:5000/salus/configuration/scanners/) for its scanners as well as scanner specific configurations.

Configurations for scanners are added to the salus config file with the config option `scanner_config`

The configuration below is an example of you could configure this option.
```yml Configuration for Gosec and Bundle Audit Scanners
reports:
  - uri: file://tests/salus-report.txt
    format: txt

scanner_config:
  Gosec:
    pass_on_raise: false
  BundleAudit:
    exceptions:
      - advisory_id: CVE-2020-2020
        changed_by: security-team
        notes: Currently no patch exists 
        expiration: "2021-04-27"
```

!!! Note
Each scanner may have scanner specific configurations, Please visit the individual page for each scanner for more information about them
!!!

---

## Continuous Integration
Salus can be used in different CI pipelines to run security checks. You would have to configure your CI pipelines to run Salus to achieve this. For example, update the config file to run salus. In circle, it will look like this:
```sh
docker run --rm -t -v $(pwd):/home/repo coinbase/salus
```
You can also provide configurations as well and utilize [environment variables](/configuration/salus_configurations/#envar-interpolation) in your salus configuration files

```yml salus-config.yaml
reports:
  - uri: {{SALUS_REPORT_URI}}
    format: sarif
  - uri: https://salus-config.internal2.net/salus-report
    format: json
```

We currenlty have documentation on how to achieve this in:
- [Circle CI](/guides/circleci_integration)
- [Github Actions](/guides/github_actions_integration)
- [Bugsnag](/guides/bugsnag_integration)


---
## Customizing Salus

First, you will need to get your [development environment setup](/guides/development/getting_setup/) to customize salus. After getting your dependencies installed, you are ready to configure salus :sparkles:

### Create Custom Scanners
Custom Scanners can be created for salus. There is a [checklist](/guides/development/adding_custom_scanners/) available to help guide this process.

With your new scanner, you can [create your own scanner-specific configurations](/guides/development/custom_configurations/). 

---
### Create Custom Configurations
It is possible to build [custom configurations](/guides/development/custom_configurations/) for your scanner or even build additional configurations for existing scanners. 

#### building additional configuration for existing scanners
A good start would be to look at the [Base scanner file](https://github.com/coinbase/salus/blob/master/lib/salus/scanners/base.rb), which is the parent file for all Salus scanners. The [`build_options`](https://github.com/coinbase/salus/blob/master/lib/salus/scanners/base.rb#L473) method is what takes in the configurations

The next step would be to look at the [source code](https://github.com/coinbase/salus/tree/master/lib/salus/scanners) for the scanner you want to customize.

---

### Running Custom Salus
In order to run your customized version of salus, you will need to create a docker image. 
```sh Build Docker Image
docker build -t salus-custom .
```

After this, you can run your version of salus in any location of your choice.
```sh Running Custom Salus
cd /path/to/run/salus/
docker run --rm -t -v $(pwd):/home/repo salus-custom
```
!!! Upstream Contributions

If you are testing a new scanner across a large fleet of services and think it produces a valuable signal for checks that other organizations may want, please submit a [PR to this repository](https://github.com/coinbase/salus/pulls) with some data about what this scanner can find. If the findings are promising and the checks are valuable, we will include it in the official version.
!!!

---