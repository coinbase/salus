# Bugsnag Integration
If you wish to report Salus and related Salus scanner errors to your Bugsnag instance to help debug any potential issues, then follow the instructions below to pass your api key and your custom reporting endpoing if you have one.

## Setup
Salus requires the env var, `BUGSNAG_API_KEY` to be defined in the docker container.

For example if you are running Salus as a docker container, you can do the following:
```
docker run --rm -t -e BUGSNAG_API_KEY=<YOUR_API_KEY> -v $(pwd):/home/repo coinbase/salus
```

### Error Reporting Endpoint
By default, it will send error reports to `https://notify.bugsnag.com`. This can be changed by defining the env var, `BUGSNAG_ENDPOINT` with your custom reporting URL.

For example if you are running Salus as a docker container, you can do the following:
```
docker run --rm -t -e BUGSNAG_API_KEY=<YOUR_API_KEY> -e BUGSNAG_ENDPOINT=<https://YOUR_CUSTOM_BUGSNAG_ENDPOINT> -v $(pwd):/home/repo coinbase/salus
```
