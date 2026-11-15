# agent-auth

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/joanfabregat/agent-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/joanfabregat/agent-auth/actions/workflows/ci.yml)
[![CodeQL](https://github.com/joanfabregat/agent-auth/actions/workflows/codeql.yml/badge.svg)](https://github.com/joanfabregat/agent-auth/actions/workflows/codeql.yml)
[![Rust edition](https://img.shields.io/badge/Rust-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![Status](https://img.shields.io/badge/status-experimental%20beta-yellow.svg)](https://github.com/joanfabregat/agent-auth/releases)

Cloud CLIs usually redirect approval to a localhost listener. When the CLI runs on a remote agent host, that listener is on the wrong machine for your browser. `agent-auth` bridges that final callback to the CLI without copying codes into chat or registering another OAuth application.

**Status:** experimental beta. Native CLI callback handling is tested with synthetic browser, relay, and listener fixtures. A successful callback is not proof that a CLI authenticated: the wrapper must check CLI completion and the expected identity before allowing commands. Live provider validation is a separate deployment step.

## How it works

1. Your wrapper starts `gcloud auth login` in browser mode or `doctl auth login --no-browser`, using a fresh private CLI configuration.
2. The wrapper saves the CLI's authorization URL in a mode-0600 file under a private tmpfs directory.
3. `agent-auth capture` registers that URL's existing state and opens a new tab through your browser's existing Chrome DevTools Protocol (CDP) connection.
4. You sign in and approve access yourself. The bridge never clicks consent buttons, reads cookies, or supplies credentials.
5. The provider redirects to the CLI's **original registered localhost URI**. In this tab only, the bridge intercepts that navigation and responds with a redirect to your HTTPS callback relay.
6. The relay delivers the bounded, one-use callback query to the bridge over its authenticated local control API. The bridge forwards it to the original CLI listener on the agent host.
7. The CLI validates state/PKCE, exchanges the code, and stores its credentials in the isolated configuration. Your wrapper verifies login completion and account/team identity, controls commands, and revokes the session when done.

**No new Google or DigitalOcean OAuth client is required.** The CLI keeps its built-in client, scopes, PKCE verifier, token exchange, and credential storage. `agent-auth` does not handle cloud access or refresh tokens. Versions before this architecture used a separate OAuth client; their `login` and `revoke` commands have been removed.

## Requirements

- Linux agent host with a private tmpfs runtime directory and the official cloud CLI.
- Chrome on the human's machine, running with remote debugging and a dedicated profile. A private SSH remote forward exposes its CDP port on the agent host's loopback interface. Never expose CDP publicly: access to it controls your browser.
- An HTTPS callback hostname reachable by the browser, optionally over a VPN. The provider redirects the browser; it does not connect to the callback server itself.
- An isolated CLI wrapper that owns login supervision, identity verification, command approval, expiry, and verified revocation. This project transports callbacks; it is not a cloud authorization policy or session manager.

The browser bridge must already be connected before login capture starts. There is no browser extension or local browser-side server to install. A plain HTTPS server cannot substitute for this bridge because the stock clients' registered redirect URIs are localhost addresses.

## Run

Start the relay with an owned mode-0700 directory on tmpfs:

```sh
agent-auth serve --runtime-dir /run/user/1000/agent-auth
```

Publish only its callback listener (`127.0.0.1:8053`) through your HTTPS proxy. Keep the control listener (`127.0.0.1:8054`) loopback-only. Disable proxy request logging, tracing, and metrics for this host, including error paths; callback URLs contain one-use secrets. Do not publish `/v1/` routes. The relay exits after five idle minutes, accepts at most 128 pending approvals, and expires pending requests after 30 minutes.

Have your wrapper start a native CLI login in its isolated configuration and write its URL to a private file. For Google, use browser mode (`--launch-browser`); `--no-launch-browser` selects Google's copy/paste flow instead. A wrapper can supply a `BROWSER` opener that saves the URL rather than launching a browser on the remote host. Headless browser detection must recognize that opener. For DigitalOcean, `--no-browser` still starts its localhost listener. Preserve PKCE and never override the CLI's redirect URI or client ID.

Then start capture, substituting your actual private paths and hostname:

```sh
agent-auth capture --provider google \
  --authorization-url-file /run/user/1000/cloud-session/authorization.url \
  --runtime-dir /run/user/1000/agent-auth \
  --browser-url http://127.0.0.1:9222 \
  --callback-base https://agent-auth.example.com
```

Use `--provider digitalocean` for `doctl`. Files must be owned mode-0600 regular files under owned mode-0700 tmpfs directories. URLs are read from files, never command arguments. Capture prints only fixed events (`approval_requested`, `callback_forwarded`); it never prints a callback code or token. A denial is forwarded to the CLI too.

The completion page scrubs the query using a redirect to `/complete`. Its receipt confirms transport only. Wait for the CLI's exit status and verify the expected identity before using credentials. If capture fails or times out, close/revoke the wrapper session and restart the login; do not retry an old code.

## Security model

The relay and bridge bind each callback to its provider, exact original loopback destination, and CLI-generated state. They reject duplicate security parameters, conflicting code/error responses, token-bearing callbacks, unsafe endpoints, and oversized inputs. Delivery is one-use, bounded, and expiring. Browser interception is limited to the newly created tab and the exact callback address; other tabs are not inspected. All bridge HTTP endpoints remain loopback-only, with proxies and redirects disabled. The provider's authentication page is never proxied.

The browser CDP connection is privileged. The code uses only tab creation, navigation, callback interception, and detach commands, but a compromised bridge could abuse that connection. Use a dedicated browser profile. Same-uid processes on the agent host are outside the isolation boundary. Unix file permissions are operational guardrails, not isolation from a hostile agent sharing the same account.

Credentials, cloud client registrations, provider access/refresh tokens, real identities, deployment hostnames, runtime state, and encrypted credential stores belong outside this public repository. Local deletion does not prove provider revocation. Your wrapper must retain enough private state to retry failed cleanup, and a host/network failure can prevent revocation.

## Build, CI, and releases

Use Rust 1.99.0 on Linux in an isolated build environment without credentials:

```sh
cargo build --locked --release
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

The implementation uses Axum/Tokio, Reqwest/Rustls for local HTTP, and tokio-tungstenite for CDP. The `oauth2` dependency supplies random opaque control tokens only; the program does not exchange provider grants. Dependencies are locked and audited before execution.

Pull requests run formatting, Clippy, tests, native amd64/arm64 builds, dependency advisory/license/source checks, dependency review, a supplemental confidentiality scan, workflow linting, and CodeQL. Actions are pinned to commit SHAs. Scheduled checks and dependency alerts remain enabled; dependency updates are reviewed manually.

Publishing a tagged GitHub release builds static Linux amd64/arm64 archives, SHA-256 checksums, and GitHub provenance attestations. Verify the checksums and attestations before installation. Release builds do not receive cloud credentials. See [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and the [MIT license](LICENSE).
