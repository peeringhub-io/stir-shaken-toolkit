# Shell Completion

The CLI supports generated shell completion through `argcomplete`.

For bash, enable completion in the current shell with:

```bash
eval "$(register-python-argcomplete stir-shaken-toolkit)"
```

To enable it persistently, add that line to your shell startup file after the
toolkit is installed in the environment used by your shell.

Completion is derived from the argparse CLI definitions, so new subcommands and
options do not require a hand-maintained completion script.

Path arguments include file-aware completions where useful:

- Certificate inputs complete `.crt` and `.pem` files.
- CSR inputs complete `.csr` and `.pem` files.
- Key inputs complete `.key` and `.pem` files.
- Config inputs complete `.yaml` and `.yml` files.
- Output directory arguments complete directories.
