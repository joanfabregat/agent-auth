# agent-auth

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust edition](https://img.shields.io/badge/Rust-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![Status](https://img.shields.io/badge/status-early%20development-yellow.svg)](https://github.com/joanfabregat/agent-auth)

Browser-approved OAuth for cloud command-line tools running on a remote agent host.

Cloud CLIs commonly redirect browser approval to `localhost`. That works when the browser and CLI share a machine, but a browser on your laptop cannot reach a listener bound to the remote agent host's loopback interface. `agent-auth` provides a shared HTTPS callback address that your browser can reach, so approval can finish without copying callback URLs into a conversation or forwarding a new SSH port for every login.

**Status:** initial implementation in progress. There are no published releases, hosted authentication service, or production-readiness claim yet. Provider login and revocation must be validated against real accounts before deployment. Existing cloud access should keep working until a replacement has passed those checks.

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

## Development

The code targets Linux and the Rust 2024 edition. The first implementation uses Axum/Tokio for HTTP, the `oauth2` crate for authorization-code flow and PKCE, and Reqwest with Rustls for provider requests. Dependencies are locked and must be audited before execution.

The build and test instructions will be completed with the initial implementation. On a sandboxed development host, run Cargo through the host's approved container runner rather than granting dependencies access to cloud credentials or the rest of your home directory. Do not add credential files or runtime sessions to Git.

## Roadmap

- Complete and test the shared relay and local login client.
- Validate Google Cloud and DigitalOcean login, identity checks, credential handoff, expiry, and revocation.
- Document reverse-proxy deployment and integration with existing cloud wrappers.
- Publish reproducible builds and versioned releases after those checks pass.

## License

[MIT](LICENSE). Copyright 2026 Joan Fabregat.
