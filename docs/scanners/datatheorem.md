# DataTheorem

This scanner integrates with a paid subscription to DataTheorem. This Salus integration will help you scan your mobile apps - iOS and Android. Please see [DataTheorem's website](https://www.datatheorem.com/solutions/mobile-application-security) for more information.

## Configuration
You will need two API keys from DataTheorem. An upload api key and a scan results api key passed as environment variables when initiating the Salus container. See the example below for how to do this.

```sh
docker run --rm -t -e DATATHEOREM_UPLOAD_API_KEY='your_upload_key' -e DATATHEOREM_RESULTS_API_KEY='your_results_key' -v $(pwd):/home/repo salus-local
```

There is an optional `mobile-app-paths` config variable. By default, Salus will scan the entire codebase passed to it for an `.apk` or `.ipa` file. For large repositories, this can be time consuming. The `mobile-app-paths` config allows a user to hardcode the paths where the mobile app binaries can be found. This direct hardcoding bypasses the recursive search and eliminates the search time.

```yaml
scanner_configs:
  DataTheorem:
    mobile-app-paths:
      - path/to/android.apk
      - path/to/another_android.apk
      - path/to/ios.ipa
```
