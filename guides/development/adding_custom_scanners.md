---
label: Adding Custom Scanners
---

If you would like Salus to run scanners which are not in the official version, you can build a custom image. These might be new scanners that you want to test or scanners that are relevant only to your organization.

A custom image can be made from a minimal Docker file that is `FROM` the `coinbase/salus` image, installs any new system dependencies and then copies your new scanner class into the appropriate location. [coinbase/custom-salus-example](https://github.com/coinbase/custom-salus-example) is an example of a custom image.

---


## Checklist
This is a checklist for creating custom scanners
### 1) Determine which types of files you want to scan.

In the [repo class](https://github.com/coinbase/salus/blob/master/lib/salus/repo.rb), look to see if your file type is already available. If not, then create a new item in the array.

`{ handle: :android_app, filename: '.apk', wildcard: true },`

The handle here will autocreate a few methods but the most important is the `{handle}_present?` which in this example is `android_app_present?`.

The handle name must be unique to avoid overwriting previous handles.

The filename key is the file to look for. For a generic android app scanner, we don't typically know the name of file beforehand, but we do know that the file has a special extension `apk`.

The wildcard option performs an expensive recursive search in the entire repo for a match against `*{filename}` which in this example is `*.apk` as a valid match. *TODO: The filename could be updated to take a regex match instead.*

For a filename that we do know the exact file name say like a known library manifest file like  `Gemfile.lock` for ruby projects, we can specify this entire filename and omit the wildcard option entirely. The default for wildcard is `false`.

---

### 2) Add the scanner to the Docker container
If you are relying on some Open Source Software (OSS) scanner that you need to have available locally, then you will need to add the installation steps in the Docker container. Please follow the instructions for the scanner on installation steps.

---

### 3) Define your scanner by defining two methods
  - `should_run?` which returns a Boolean
  - `run` which defines how to run the scanner

Make sure to integrate at least common options for the scanner. You can do this by using the `build_options` helper function defined in the Base Scanner class [`scanners/base.rb`](https://github.com/coinbase/salus/tree/master/lib/salus/scanners/base.rb). There is also additional documentation on [how to setup configurations for your scanner](/guides/development/custom_configurations)

---

### 4) Write Integration Tests
- All public methods should be tested.
- Tests should not just test the scanner options work but also test for conflicting or misconfigurations.
- Tests should include a pass scan and a fail scan.
- A good example can be found in [`spec/lib/salus/scanners/gosec_spec.rb`](https://github.com/coinbase/salus/blob/master/spec/lib/salus/scanners/gosec_spec.rb)
- You will need to define fixtures as a sample applications to run the scanners against. These fixtures should be very small self-contained programs. Each scanner will have its own folder under `spec/fixtures`.

#### Running scanner in test environment
To run non-public scanner tests in your own environment, you can use the following template to help you.

```sh
git clone https://github.com/coinbase/salus.git
cd salus
docker build -t salus-local .
docker build -f Dockerfile.tests -t salus-tests .
```
!!! Note
We currently don't publish the test container.
In the future, we plan to publish the test container to make this setup easier.
!!!

Create the following file `Dockerfile.custom_tests`
The structure of your spec folder should be as follows:
- [x] `./spec/fixtures/`
- [x] `./spec/lib/salus/scanners/<scanner_spec>.rb`

```Dockerfile Dockerfile.custom_tests
FROM salus-tests
RUN bundle install --with test
COPY <your_spec_folder> /home/spec
COPY <your_custom_scanner>.rb /home/lib/salus/scanners/
ENTRYPOINT ["bundle", "exec", "rspec", "--format", "documentation", "spec/"]
```
Then run these command to build and run your tests
```sh
docker build -f Dockerfile.custom_tests -t salus-custom-tests .`
docker run salus-custom-test` # runs all tests
```
---

### 5) Submit your PR
if you can make the scanner public. For non-public scanners, you can build from the public Docker container and copy over relevant files, like below.

```Dockerfile Dockerfile
FROM coinbase/salus:2.10.14@sha256:940c68181cfb76ef50eb58b0d9c2f45a98ad7c09073e6ec78fb6a2f6ea844e5c


# If we have custom modules, use this to install them into our internal Salus.
COPY <your_custom_scanner>.rb /home/lib/salus/scanners/

```
!!! Upstream Contributions

If you are testing a new scanner across a large fleet of services and think it produces a valuable signal for checks that other organizations may want, please submit a [PR to this repository](https://github.com/coinbase/salus/pulls) with some data about what this scanner can find. If the findings are promising and the checks are valuable, we will include it in the official version.
!!!


---
## Example of a Custom Scanner

All scanners should be a subclass of [`Salus::Scanners::Base`](https://github.com/coinbase/salus/tree/master/lib/salus/scanners/base.rb). This parent class will provide the necessary methods for reporting scan results. The two methods that __must__ be implemented are `#run` and `#should_run?`.

__Available Methods:__

- `#run_shell(command, env: {}, stdin_data: '')` - used to run shell commands in the container, useful for executing a scanner.
- `#report_success` - adds to the report the fact that this scan was successful (found no vulnerabilities).
- `#report_failure` - adds to the report the fact that this scan was unsuccessful (found a vulnerability).
- `#log`- adds data to the report and is shown in normal (not verbose) mode. This method should be used to show the developer information that they can act on to fix any security issues found from the scan.
- `#report_info(type, message)` - adds data to the report and is only shown to the developer in verbose mode. This method is primarily used for information that will be parsed by a Salus report consumer.
- `#report_stdout(stdout)` - adds the STDOUT of the scanner to the report.
- `#report_stderr(stderr)` - adds the STDERR of the scanner to the report.
- `#report_error(error_data)` - adds an error encountered while scanning to the report.
- `#report_recorded_failure?` - `true` if the report has recorded a failure for this scanner.
- `#record_dependency_info(info, dependency_file)` - adds information about a dependency to the report.
- `@repository` - instance variable containing a `Salus::Repo` object.
- `@repository.path_to_repo` - file system path to the target repository.

__Example__

Scanner class that checks that a Dockerfile, if present, pins its base container.

```ruby
require 'salus/scanners/base'

module Salus::Scanners
  class PinnedBaseContainer < Base
    def run
      dockerfile = File.read("#{@repository.path_to_repo}/Dockerfile")
      from_line = dockerfile.each_line.select { |line| line.start_with?('FROM') }.first.strip

      # Typical FROM line is:
      # FROM abc/xyz:production@sha256:084b872...8ab750d
      # Check that we are pinning the base container to a sha256 fingerprint.
      if from_line.match?(/@sha256:[0-9a-f]{64}/)
        report_success

        # Report the base container image.
        image = from_line.sub('FROM ', '')
        report_info('base_container', image)
      else
        report_failure
      end
    end

    def should_run?
      File.exist?("#{@repository.path_to_repo}/Dockerfile")
    end
  end
end
```

---



## Example Dockerfile for a Custom Salus Container
This Dockerfile should be in the root of your salus directory
```Dockerfile Dockerfile
# Inherit from official Salus image.
FROM coinbase/salus

# Install any new system level dependencies.
RUN ...

# Add custom scanners to the Salus application.
COPY scanners/* /home/lib/salus/scanners/
```

You can then build and run your custom Salus container.

```sh 
docker build -t salus-custom .

docker run --rm -t -v $(pwd):/home/repo salus-custom
```

---
