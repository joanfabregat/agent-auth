# Security

`agent-auth` transports approval callbacks for privileged native CLI sessions. It is experimental software. Builds and synthetic tests do not establish production readiness or verify live cloud identity and revocation behavior.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/joanfabregat/agent-auth/security/advisories/new). Do not open public issues containing secrets, account details, private deployment addresses, or exploits against live deployments. If private reporting is unavailable, ask for a private channel without including vulnerability details. Include affected versions, preconditions, a synthetic reproduction, impact, and any suggested fix. Do not test other people's accounts or hosts. There is no bug bounty.

## Trust boundaries

The stock cloud CLI owns its OAuth client, PKCE verifier, token exchange, and credential storage. The bridge transports only the final authorization callback and never reads CLI credential files. Its completion event does not prove successful login or identity. The enclosing wrapper must verify CLI exit status and identity, enforce command approval and expiry, and perform verified revocation.

Only the callback HTTP listener belongs behind an HTTPS reverse proxy. The authenticated control listener and browser CDP endpoint must remain loopback-only and unrouted. Disable access logs, tracing, and metrics on the callback hostname, including error paths. Codes and state must not appear in telemetry. Runtime secrets require owned private tmpfs files and directories. Callback delivery is bound to provider/state, one-use, bounded, and expiring.

CDP access controls a browser. The bridge limits itself to a newly created tab and the exact native callback address, but its connection is powerful; use a dedicated debugging profile and private SSH tunnel. Never expose the debugging endpoint to the internet. Same-uid processes on the agent host are outside the isolation boundary. Repository CI and release builds must not receive deployment credentials.

A shutdown or network failure may leave CLI grants requiring provider-side revocation. Retain private cleanup state when verification fails. Deleting files is not remote revocation.

## Confidentiality

Keep client registrations/secrets, provider tokens, callback/control secrets, session files, encrypted stores, real account/team identifiers, private hostnames, and private filesystem paths outside this repository. Use synthetic identities and `example.com` in documentation and tests. Do not attach runtime state, authorization URLs, token responses, or private browser dumps to issues, PRs, artifacts, screenshots, or logs.

Secret scanning and push protection complement the supplemental working-tree/history scan; they cannot prove arbitrary secrets are absent. Review changes before publishing. If a credential is exposed, revoke or rotate it immediately; removing it from Git is insufficient.
