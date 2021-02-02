## How to Add a Scanner to Salus


1. Determine which types of files you want to scan.

In the [repo class](https://github.com/coinbase/salus/blob/master/lib/salus/repo.rb), look to see if your file type is already available. If not, then create a new item in the array.

`{ handle: :android_app, filename: '.apk', wildcard: true },`

The handle here will autocreate a few methods but the most important is the `{handle}_present?` which in this example is `android_app_present?`.

The handle name must be unique to avoid overwriting previous handles.

The filename key is the file to look for. For a generic android app scanner, we don't typically know the name of file beforehand, but we do know that the file has a special extension `apk`.

The wildcard option performs an expensive recursive search in the entire repo for a match against `*{filename}` which in this example is `*.apk` as a valid match. *TODO: The filename could be updated to take a regex match instead.*

For a filename that we do know the exact file name say like a known library manifest file like  `Gemfile.lock` for ruby projects, we can specify this entire filename and omit the wildcard option entirely. The default for wildcard is `false`.

2. Add the scanner to the Docker container
If you are relying on some Open Source Software (OSS) scanner that you need to have available locally, then you will need to add the installation steps in the Docker container. Please follow the instructions for the scanner on installation steps.

3. Define your scanner by defining two methods
  - `should_run?` which returns a Boolean
  - `run` which defines how to run the scanner

Make sure to integrate at least common options for the scanner. You can do this by using the `build_options` helper function defined in the Base Scanner class (`scanners/base.rb`). The documentation on how to use this function can be found in `docs/scanners/base.md` under the `Reading/setting up custom configs for your scanner` section.

4. Write Integration Tests
- All public methods should be tested.
- Tests should not just test the scanner options work but also test for conflicting or misconfigurations.
- Tests should include a pass scan and a fail scan.
- A good example can be found in `spec/lib/salus/scanners/gosec_spec.rb`
- You will need to define fixtures as a sample applications to run the scanners against. These fixtures should be very small self-contained programs. Each scanner will have its own folder under `spec/fixtures`.

5. Submit your PR if you can make the scanner public. For non-public scanners, you can build from the public Docker container and copy over relevant files, like below.

```
FROM coinbase/salus:2.10.14@sha256:940c68181cfb76ef50eb58b0d9c2f45a98ad7c09073e6ec78fb6a2f6ea844e5c


# If we have custom modules, use this to install them into our internal Salus.
COPY <your_custom_scanner>.rb /home/lib/salus/scanners/
```

To run non-public scanner tests in your own environment, you can use the following template to help you.

1. `git clone https://github.com/coinbase/salus.git`
2. `cd salus`
3. `docker build -t salus-local .`
4. `docker build -f Dockerfile.tests -t salus-tests .`
* Note: We currently don't publish the test container. TODO: Publish the test container to make this setup easier.

5. Define the following `Dockerfile.custom_tests`

```
FROM salus-tests

RUN bundle install --with test

# The structure of your spec folder should be as follows:
# 1. fixtures/
# 2. lib/salus/scanners/<scanner_spec>.rb
COPY <your_spec_folder> /home/spec

COPY <your_custom_scanner>.rb /home/lib/salus/scanners/

ENTRYPOINT ["bundle", "exec", "rspec", "--format", "documentation", "spec/"]
```

5. `docker build -f Dockerfile.custom_tests -t salus-custom-tests .`
6. `docker run salus-custom-test` # runs all tests
