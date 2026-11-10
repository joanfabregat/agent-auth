# Security

`agent-auth` handles approval for privileged cloud sessions. It is early development software, and its provider integrations have not yet passed live deployment validation. Do not assume that a successful build or dependency scan establishes production readiness.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/joanfabregat/agent-auth/security/advisories/new). Do not open a public issue containing credentials, account details, private deployment addresses, or an exploit against a live deployment. If private reporting is unavailable, open a minimal issue asking the maintainer for a private channel, without vulnerability details or secrets.

Include affected versions or commits, preconditions, a minimal reproduction using synthetic data, impact, and any suggested fix. Do not test against other people's hosts or cloud accounts. This project does not offer a bug bounty.

## Confidentiality

Keep live OAuth clients, client secrets, provider tokens, callback control secrets, session directories, encrypted credential stores, real account/team identifiers, deployment domains, and private filesystem paths outside this repository. Use `example.com` and synthetic identities in documentation and tests. Do not attach runtime state or token responses to issues, pull requests, CI artifacts, screenshots, or logs.

GitHub secret scanning and push protection complement a supplemental working-tree/history confidentiality check. These checks recognize common credential formats; they cannot establish that arbitrary custom secrets or deployment details are absent. Review changes before publishing. If a credential is exposed, revoke or rotate it at its provider immediately; removing it from Git is not sufficient.

## Trust boundaries

Only the callback listener belongs behind the HTTPS reverse proxy. The authenticated control listener must stay loopback-only and unrouted. The relay holds one-use codes and pending state, while the login process holds OAuth client secrets and cloud tokens. Runtime secrets require owner-only files on tmpfs. PKCE, OAuth state, provider binding, identity checks, request expiry, and one-use delivery must remain intact.

Same-uid processes are outside the isolation boundary. Repository CI does not require cloud credentials. Published release workflows may upload artifacts but must not receive deployment secrets. A shutdown or network failure may leave remotely issued grants that require provider-side revocation.
