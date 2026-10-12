# Contributing

Keep changes focused and explain the problem they address. Separate documentation, organization and functional changes so reviewers can assess each independently.

## Conventions

- Follow the naming and formatting of the surrounding source.
- Keep loader and driver responsibilities separate.
- Update Visual Studio project and filter references when moving files.
- Preserve third-party notices and avoid unrelated edits to vendored code.
- Never commit binaries, credentials, signing keys or machine-specific settings.

## Pull requests

Include a summary, affected components and verification actually performed. If you compiled a configuration, identify the platform and toolchain. If verification was limited to static checks, say so explicitly.

Do not claim broad Windows compatibility based on a single environment. Do not include sensitive system data in logs or screenshots.

## Security

Follow [SECURITY.md](SECURITY.md) for private reporting. Contributions should remain within authorized research and must not add malicious deployment, destructive behavior or detection-evasion features.
