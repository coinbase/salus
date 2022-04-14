---
label: Github Actions Integration
---

Salus can also be used with Github Actions. 

To do this, create a YAML file in the folder `.github/workflows/` with the configurations below

```yml .github/workflows/salus.yml
on: [push]

jobs:
  salus_scan_job:
    runs-on: ubuntu-latest
    name: Salus Security Scan Example
    steps:
    - uses: actions/checkout@v1
    - name: Salus Scan
      id: salus_scan
      uses: federacy/scan-action@0.1.1
```

These configurations can be customized as well. Here is a link to the [Github Action documentation](https://github.com/federacy/scan-action) for more context on how to achieve this. 