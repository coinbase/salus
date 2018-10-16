# Repository Not Blank

This scanner just checks that there is at least 1 file for Salus to scan. If the repository is blank, this scan will fail because it indicates that Salus' configuration is likely incorrect. This can prevent silent failures from misconfiguration.

For instance, if the repository was volumed in incorrectly, this scan would fail.

```sh
# success since repo is volumed in correctly
docker run --rm -t -v $(pwd):/home/repo coinbase/salus
echo $? # returns 0

# failure since repo is volumed in incorrectly
docker run --rm -t -v $(pwd):/repo coinbase/salus
echo $? # returns 1
```
