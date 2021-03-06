# password-rules-checker

A small CLI tool that runs every rule in [`quirks/password-rules.json`](https://github.com/apple/password-manager-resources/blob/main/quirks/password-rules.json) through 1Password's [`password-rules-parser` crate](https://github.com/1Password/password-rules-parser).

Rules that fail to parse will be flagged.

```
cargo run path/to/password-rules.json
```

This tool can also diff two quirk files of equivalent length, checking to make sure each rule for each site is semantically equivalent in both files:

```
cargo run path/to/password-rules.json --diff-against path/to/other-password-rules.json
```
