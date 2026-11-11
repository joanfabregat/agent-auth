# agent-auth

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/joanfabregat/agent-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/joanfabregat/agent-auth/actions/workflows/ci.yml)
[![CodeQL](https://github.com/joanfabregat/agent-auth/actions/workflows/codeql.yml/badge.svg)](https://github.com/joanfabregat/agent-auth/actions/workflows/codeql.yml)
[![Rust edition](https://img.shields.io/badge/Rust-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![Status](https://img.shields.io/badge/status-experimental%20beta-yellow.svg)](https://github.com/joanfabregat/agent-auth/releases)

Browser-approved OAuth for cloud command-line tools running on a remote agent host.

Cloud CLIs commonly redirect browser approval to `localhost`. That works when the browser and CLI share a machine, but a browser on your laptop cannot reach a listener bound to the remote agent host's loopback interface. `agent-auth` provides a shared HTTPS callback address that your browser can reach, so approval can finish without copying callback URLs into a conversation or forwarding a new SSH port for every login.

**Status:** experimental beta. The relay, login client, and revocation command are implemented and covered by local tests. [Versioned builds](https://github.com/joanfabregat/agent-auth/releases) are intended for controlled testing; this project does not provide a hosted authentication service or claim production readiness. Google and DigitalOcean login and revocation still need validation against real accounts before administrative use.

## Intended workflow

1. An agent requests an elevated login through its local cloud wrapper.
2. You open the provider's authorization URL and approve access in your own browser.
3. The provider redirects your browser to your HTTPS callback endpoint.
4. The callback relay delivers the one-use authorization code to the originating local login process.
5. That process exchanges the code, verifies the expected account, and stores short-lived credentials in a private session on the agent host.
6. The wrapper permits approved operations until the session is ended or expires, then revokes credentials and removes local state.

The browser displays an approval receipt; it does not display cloud access or refresh tokens. Provider sign-in and MFA stay with the provider. An existing browser session may satisfy sign-in without requiring a new security-key touch.

## Architecture

The project is a Rust binary with two responsibilities:

- **Callback relay:** an HTTP listener for browser callbacks, plus a separate authenticated control listener bound to loopback. It holds bounded, expiring pending requests and one-use authorization codes in memory. It does not need cloud access tokens, refresh tokens, or OAuth client secrets.
- **Local login client:** generates PKCE and OAuth state, requests approval through the relay, exchanges the returned code directly with the provider, checks account identity, and writes credentials only to the originating private session.

Google Cloud and DigitalOcean are the initial provider adapters. Each provider needs its own registered OAuth client and exact HTTPS redirect URI. This is not a flag that changes the callback URL of an existing stock CLI login. Normal resource operations remain in `gcloud` or `doctl`; wrappers integrate the resulting credentials with those tools.

A deployment might use:

```text
https://agent-auth.example.com/callback/google
https://agent-auth.example.com/callback/digitalocean
```

The browser must be able to reach these addresses. They can be VPN-only: the provider redirects the browser rather than making the callback request itself. TLS termination, DNS, VPN access, and OAuth client registration belong to the deployment. Host-specific configuration stays outside the reusable Rust implementation.

## Access model

`agent-auth` is designed to complement an existing least-privilege identity: for example, a VM service account or a scoped read-only PAT. Elevated login is a separate operation requiring human browser approval. Credential availability does not itself authorize a command; enforce task approval in your agent tooling and actual permissions through cloud IAM, token scopes, and Kubernetes RBAC.

The intended boundaries are:

- Browser callbacks and local control operations use separate listeners. Publish only the callback listener through the reverse proxy.
- PKCE, unpredictable state, provider binding, and one-use delivery bind each approval to its originating request.
- Pending requests have an expiry and a capacity limit. Tokens and OAuth client secrets stay out of browser pages, URLs, logs, and command arguments.
- Control secrets and credential files require owner-only permissions on a memory filesystem. The login process keeps provider credentials separate from relay state.
- Agents sharing one Unix account are not isolated from each other by private paths alone. A hostile process with the same uid can generally access that account's files and processes.
- Local expiry or deletion does not prove remote revocation. Provider-specific cleanup must be verified, including refresh-token behavior. A host or network failure can prevent remote cleanup.

This is a security-sensitive component. Do not expose its control API publicly, copy production credentials into issues, or treat an untested provider integration as ready for privileged use.

## Build

The code targets Linux and the Rust 2024 edition. The first implementation uses Axum/Tokio for HTTP, the `oauth2` crate for authorization-code flow and PKCE, and Reqwest with Rustls for provider requests. Dependencies are locked and must be audited before execution.

Use Rust 1.99.0 on Linux:

```sh
cargo build --locked --release
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

Run these commands in an isolated build environment without cloud credentials. On managed agent hosts, use the host's approved container runner. The binary is `target/release/agent-auth`; it needs outbound HTTPS to the provider for login and revocation, but the relay itself does not.

## Configure and run

Register separate OAuth applications for the providers you use. Google requires a **web application** OAuth client with a client secret for an HTTPS redirect; configure the consent screen and permitted users as appropriate. DigitalOcean requires an OAuth application configured for the authorization-code flow and PKCE. Register the exact corresponding callback URI shown above. Existing `gcloud` and `doctl` application registrations cannot be reused with arbitrary callback addresses.

Create a private directory on Linux tmpfs, for example with `umask 077; mktemp -d /tmp/agent-auth-XXXXXXXX` on a host where `/tmp` is tmpfs. All runtime, session, and client-file parent directories must be owned by the current user, mode `0700`, and on tmpfs; secret files must be regular, owned files with mode `0600`. Files and directories are checked before use. Decrypt deployment secrets into that memory directory outside the repository; never pass their values as CLI arguments or commit encrypted credential stores here.

The examples below use `/run/user/1000/agent-auth` as an illustrative tmpfs location. Create it and its `session` subdirectory with mode `0700` first; substitute your actual runtime directory.

Client configuration is JSON. A Google configuration has these fields:

```json
{
  "client_id": "YOUR_REGISTERED_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "expected_email": "operator@example.com"
}
```

A DigitalOcean configuration has these fields (`client_secret` may also be supplied for a confidential client):

```json
{
  "client_id": "YOUR_REGISTERED_CLIENT_ID",
  "expected_email": "operator@example.com",
  "expected_team_id": "YOUR_EXPECTED_TEAM_UUID"
}
```

Start the relay in a supervised, on-demand process:

```sh
agent-auth serve --runtime-dir /run/user/1000/agent-auth
```

The callback listener defaults to `127.0.0.1:8053`; the authenticated control listener defaults to `127.0.0.1:8054`. Both are restricted to loopback. Configure your HTTPS reverse proxy to forward **only** `/callback/google` and `/callback/digitalocean` to port `8053`, with optional `/healthz`. Never proxy port `8054`. Disable access logging or redact callback query strings: authorization codes and state appear in them. Avoid third-party scripts, analytics, and error reporting that capture callback URLs. TLS, DNS, proxy hardening, and VPN policy are deployment responsibilities.

For example, to approve a DigitalOcean session:

```sh
agent-auth login --provider digitalocean \
  --client-file /run/user/1000/agent-auth/digitalocean-client.json \
  --runtime-dir /run/user/1000/agent-auth \
  --session-dir /run/user/1000/agent-auth/session \
  --callback-base https://agent-auth.example.com
```

Use `--provider google` with the Google client file for Google Cloud. Login prints a JSON `authorize` event containing the provider URL; open it in your browser. Approval waits up to 30 minutes. After token exchange and account verification, a JSON `ready` event reports the identity and session deadline. Credentials are never printed. Google requests `openid`, `email`, and `cloud-platform` with online access; DigitalOcean requests `read` and `write`. Google IAM and DigitalOcean account permissions still bound the actual access.

The session contains private `grant.json`, `access-token`, and `ready.json` files, plus `doctl.yaml` for DigitalOcean. A wrapper can invoke `doctl --config SESSION/doctl.yaml --context elevated ...`, or `gcloud --access-token-file=SESSION/access-token ...` for Google. These are integration points, not complete elevated wrappers: **the wrapper must reject closed or unready sessions, check the deadline before every command, enforce task approval, and supervise expiry and cleanup.** The deadline is at most 45 minutes from the start of login, bounded by provider token expiry. The binary does not automatically shorten provider token lifetime or run a background revocation timer.

End a session with:

```sh
agent-auth revoke \
  --client-file /run/user/1000/agent-auth/digitalocean-client.json \
  --session-dir /run/user/1000/agent-auth/session
```

Revocation marks the session closed before contacting the provider and verifies that access and any refresh credentials are rejected. Successful cleanup removes local credential files. If verification fails, the closed session is retained for retry or provider-side application revocation. A login failure after token issuance can also retain `grant.json` for cleanup; do not simply delete it. A process or host failure can prevent remote revocation. Encrypted-at-rest client configuration, session supervision, and recovery procedures belong in the deployment, outside this repository.

The relay exits after five idle minutes with no pending approvals and responds to SIGINT/SIGTERM. Pending requests expire after 30 minutes; at most 128 are accepted. Stopping the relay does not revoke grants held by login sessions.

## CI and releases

Pull requests run formatting, Clippy, tests and release builds on Linux amd64 and arm64, dependency advisory/license/source checks, dependency review, a supplemental confidentiality scan, workflow linting, and CodeQL for Rust and GitHub Actions. Scheduled checks detect newly disclosed dependency and workflow issues. Actions are pinned to commit SHAs, and routine jobs have a read-only repository token.

Publishing a GitHub release tagged `vVERSION` builds static Linux amd64/arm64 archives after checking that the tag matches `Cargo.toml` and belongs to `main`. Archives include the README, MIT license, and security policy. The workflow publishes SHA-256 checksums and GitHub build provenance attestations; verify both before installation. Its manual dispatch on `main` builds artifacts as a dry run without publishing a release. Release jobs do not use deployment or cloud credentials.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting, trust boundaries, and confidentiality rules. See [CONTRIBUTING.md](CONTRIBUTING.md) for review and repository protection policy.

## Roadmap

- Validate Google Cloud and DigitalOcean login, identity checks, credential handoff, expiry, and revocation.
- Complete deployment supervision and integration with existing cloud wrappers.
- Publish a stable release after those checks pass.

## License

[MIT](LICENSE). Copyright 2026 Joan Fabregat.
