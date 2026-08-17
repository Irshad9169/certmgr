#!/bin/sh
# Exercises certmgr-challenge-helper directly (no ssh, no production paths)
# by faking SSH_ORIGINAL_COMMAND the way sshd would set it. Run this on
# lets-encrypt01 (or anywhere with the script + a throwaway user account)
# before wiring the real authorized_keys entry.
#
# Usage: ./test-certmgr-challenge-helper.sh /path/to/certmgr-challenge-helper

set -eu

HELPER="${1:?Usage: $0 /path/to/certmgr-challenge-helper}"
SCRATCH="$(mktemp -d)"
export CERTMGR_HELPER_WEBROOT="$SCRATCH/var/www/html"
export CERTMGR_HELPER_OWNER="$(id -un)"   # avoid chown-to-secauto failing as non-root
mkdir -p "$CERTMGR_HELPER_WEBROOT"

pass=0
fail=0

run_case() {
    desc="$1"
    cmd="$2"
    expect="$3"   # "accept" or "reject"

    export SSH_ORIGINAL_COMMAND="$cmd"
    export SSH_CLIENT="127.0.0.1 12345 22"

    if "$HELPER" >/tmp/helper_stdout 2>/tmp/helper_stderr; then
        actual="accept"
    else
        actual="reject"
    fi

    if [ "$actual" = "$expect" ]; then
        echo "PASS: $desc"
        pass=$((pass + 1))
    else
        echo "FAIL: $desc (expected $expect, got $actual)"
        echo "  cmd:    $cmd"
        echo "  stderr: $(cat /tmp/helper_stderr)"
        fail=$((fail + 1))
    fi
}

TOKEN="c7r6kpvvqonkj4fy_AkGwCetgkjawZ7C6BaM9m6JZ3A"
THUMB="MEm2OPHSzXycZtTEgDGxrIN5E2IEaXgAR-Ld20M4tv0"
VALIDATION="${TOKEN}.${THUMB}"

# ── Valid shapes ─────────────────────────────────────────────────────────
run_case "valid auth command" \
    "cd $CERTMGR_HELPER_WEBROOT; echo $VALIDATION > .well-known/acme-challenge/$TOKEN; chown -R $CERTMGR_HELPER_OWNER: .well-known;" \
    accept

if [ -f "$CERTMGR_HELPER_WEBROOT/.well-known/acme-challenge/$TOKEN" ]; then
    written="$(cat "$CERTMGR_HELPER_WEBROOT/.well-known/acme-challenge/$TOKEN")"
    if [ "$written" = "$VALIDATION" ]; then
        echo "PASS: challenge file content matches"
        pass=$((pass + 1))
    else
        echo "FAIL: challenge file content mismatch: got '$written'"
        fail=$((fail + 1))
    fi
else
    echo "FAIL: challenge file was not created"
    fail=$((fail + 1))
fi

run_case "valid cleanup command" \
    "cd $CERTMGR_HELPER_WEBROOT/.well-known/acme-challenge; rm -f ./$TOKEN;" \
    accept

if [ ! -f "$CERTMGR_HELPER_WEBROOT/.well-known/acme-challenge/$TOKEN" ]; then
    echo "PASS: challenge file was removed"
    pass=$((pass + 1))
else
    echo "FAIL: challenge file still present after cleanup"
    fail=$((fail + 1))
fi

# ── Must be rejected ─────────────────────────────────────────────────────
run_case "mismatched token/validation prefix" \
    "cd $CERTMGR_HELPER_WEBROOT; echo ${TOKEN}.${THUMB} > .well-known/acme-challenge/DIFFERENTTOKENVALUEHEREXXXXXXXXXX; chown -R $CERTMGR_HELPER_OWNER: .well-known;" \
    reject

run_case "path traversal in token" \
    "cd $CERTMGR_HELPER_WEBROOT; echo $VALIDATION > .well-known/acme-challenge/../../../etc/passwd; chown -R $CERTMGR_HELPER_OWNER: .well-known;" \
    reject

run_case "command injection via semicolon" \
    "cd $CERTMGR_HELPER_WEBROOT; echo $VALIDATION > .well-known/acme-challenge/$TOKEN; chown -R $CERTMGR_HELPER_OWNER: .well-known; rm -rf / #" \
    reject

run_case "command injection via backticks" \
    'cd '"$CERTMGR_HELPER_WEBROOT"'; echo `whoami` > .well-known/acme-challenge/'"$TOKEN"'; chown -R '"$CERTMGR_HELPER_OWNER"': .well-known;' \
    reject

run_case "completely unrelated command" \
    "cat /etc/shadow" \
    reject

run_case "interactive shell attempt (no forced command bypass)" \
    "" \
    reject

echo
echo "----------------------------------------"
echo "$pass passed, $fail failed"
rm -rf "$SCRATCH" /tmp/helper_stdout /tmp/helper_stderr
[ "$fail" -eq 0 ]
