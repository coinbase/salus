# Customizing Salus

If you would like Salus to run scanners which are not in the official version, you can build a custom image. These might be new scanners that you want to test or scanners that are relevant only to your organization.

A custom image can be made from a minimal Docker file that is `FROM` the `coinbase/salus` image, installs any new system dependencies and then copies your new scanner class into the appropriate location. [coinbase/custom-salus-example](https://github.com/coinbase/custom-salus-example) is an example of a custom image.

## Example of a Custom Scanner

All scanners should be a subclass of [`Salus::Scanners::Base`](../lib/salus/scanners/base.rb). This parent class will provide the necessary methods for reporting scan results. The two methods that __must__ be implemented are `#run` and `#should_run?`.

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

## Example Dockerfile for a Custom Salus Container

```Dockerfile
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

## Upstream Contributions

If you are testing a new scanner across a large fleet of services and you think that it produces valuable signal for checks that other organizations may want, please submit a PR to this repository with some data about what this scanner can find. If the SnR is good and the checks are valuable, we will include it in the official version.
