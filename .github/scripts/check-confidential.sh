#!/usr/bin/env bash
# Supplemental checks for common credentials and private runtime files.
# Report filenames/rule names only: never print matching values or patches.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
pattern='(dop|doo|dor)_v1_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|GOCSPX-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|ya29\.[A-Za-z0-9._-]{20,}|(AKIA|ASIA)[A-Z0-9]{16}|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|/home/[A-Za-z0-9_-]+/(repos|scratch|\.local|\.config)/'
failed=0
while IFS= read -r -d '' path; do
    [[ -f $path ]] || continue
    case "$path" in
        .env|.env.*|*.enc.yaml|*.enc.json|*.pem|*.key|runtime/*|sessions/*|grant.json|rotated-grant.json|control.token|access-token|client.json|client-secret.json|doctl.yaml|*/grant.json|*/rotated-grant.json|*/control.token|*/access-token|*/client.json|*/client-secret.json|*/doctl.yaml)
            printf 'Private runtime/config filename must not be published: %s\n' "$path" >&2
            failed=1 ;;
    esac
    if LC_ALL=C grep -IEq -- "$pattern" "$path"; then
        printf 'Potential credential or private host path in: %s\n' "$path" >&2
        failed=1
    fi
done < <(git ls-files --cached --others --exclude-standard -z)

# Keep history in a pipe; grep consumes the whole stream
# to avoid SIGPIPE being mistaken for a clean scan under pipefail.
set +e
git log --all --format= --patch --no-ext-diff --no-textconv | LC_ALL=C grep -E -- "$pattern" >/dev/null
statuses=("${PIPESTATUS[@]}")
set -e
if [[ ${statuses[0]} -ne 0 || ${statuses[1]} -gt 1 ]]; then
    echo 'History scan failed; refusing to report a clean result.' >&2
    exit 1
fi
if [[ ${statuses[1]} -eq 0 ]]; then
    echo 'Potential confidential material in Git history; inspect privately.' >&2
    failed=1
fi
if [[ $failed -ne 0 ]]; then exit 1; fi
echo 'Confidentiality checks passed (working tree and all local Git history).'
