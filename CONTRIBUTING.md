# Contributing

Open a pull request against `main`, describe the resulting behavior and validation, and use synthetic data in tests and examples. Run the checks documented in the README. Keep credentials, real account identifiers, private domains, host paths, encrypted secret stores, and runtime state outside the repository, including Git history. The supplemental scan reports filenames rather than matching values; review changes manually as well.

Report security problems privately as described in [SECURITY.md](SECURITY.md). Do not put live callback URLs, token responses, or credential files into an issue, PR, or CI artifact.

## Maintainer policy

The `main` ruleset requires pull requests, signed commits, linear history, resolved review threads, and required CI checks. Force pushes and deletion are blocked, with no administrator bypass. Squash merge is the only enabled merge method. The initial single-maintainer policy requires zero external approvals so the maintainer can merge their own PR after checks pass; it does not allow direct pushes.

The ruleset definition is versioned in [.github/rulesets/main.json](.github/rulesets/main.json). Repository settings are applied through GitHub administration; committing this file alone does not configure GitHub. Workflow tokens default to read-only and cannot approve pull requests. Secret scanning, push protection, Dependabot alerts/security updates, and private vulnerability reporting are enabled. Actions must be pinned to full commit SHAs.

Before a release, validate provider behavior and deployment integration. Update `Cargo.toml` and `Cargo.lock` through a PR, then tag the merged commit with `vVERSION` and publish its GitHub release. The release workflow verifies tag/version/main ancestry, audits dependencies, tests and builds static binaries, and publishes assets with checksums and provenance. A manual dispatch on `main` exercises the build without publication.

Do not add cloud credentials to repository or environment secrets. Review action updates and dependency changes before merging them. Read-only PR jobs must stay separate from release publication permissions; do not use `pull_request_target` to run contributor code with privileged tokens.
