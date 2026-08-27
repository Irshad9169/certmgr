#!/bin/sh
# Exercises certmgr-challenge-proxy.cgi directly (no real web server, no
# production hosts) by faking the CGI environment variables the way
# Apache/nginx+fcgiwrap would set them, and standing up a throwaway local
# HTTP server as the "upstream" (CertMgr automation host). Run this on
# lets-encrypt01 before wiring the real ScriptAlias/location block.
#
# Usage: ./test-certmgr-challenge-proxy.sh /path/to/certmgr-challenge-proxy.cgi

set -eu

CGI="${1:?Usage: $0 /path/to/certmgr-challenge-proxy.cgi}"
chmod +x "$CGI" 2>/dev/null || true

# Prefer whichever of python3/python actually runs (some environments —
# e.g. Windows without a real Python install — have a python3 on PATH
# that's just a store-install stub that prints a message and exits 0
# without ever behaving like Python).
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "print(1)" >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done
[ -n "$PYTHON" ] || { echo "SKIP: no working python3/python available to fake the upstream server"; exit 0; }

SCRATCH="$(mktemp -d)"
UPSTREAM_ROOT="$SCRATCH/upstream/.well-known/acme-challenge"
mkdir -p "$UPSTREAM_ROOT"

VALID_TOKEN="c7r6kpvvqonkj4fy_AkGwCetgkjawZ7C6BaM9m6JZ3A"
VALIDATION="${VALID_TOKEN}.MEm2OPHSzXycZtTEgDGxrIN5E2IEaXgAR-Ld20M4tv0"
printf '%s' "$VALIDATION" > "$UPSTREAM_ROOT/$VALID_TOKEN"

UPSTREAM_PORT=18765
( cd "$SCRATCH/upstream" && exec "$PYTHON" -m http.server "$UPSTREAM_PORT" --bind 127.0.0.1 >/tmp/proxy_upstream.log 2>&1 ) &
UPSTREAM_PID=$!
trap 'ec=$?; kill "$UPSTREAM_PID" 2>/dev/null || true; sleep 0.3; rm -rf "$SCRATCH" /tmp/proxy_stdout /tmp/proxy_stderr /tmp/proxy_upstream.log 2>/dev/null || true; exit $ec' EXIT

# Give the fake upstream a moment to bind before the first request. A raw
# TCP connect (not an HTTP GET) deliberately avoids routing through any
# system HTTP proxy that a Python http.request-based check might pick up
# for the loopback address on some hosts.
ready=0
i=0
while [ "$i" -lt 20 ]; do
    if "$PYTHON" -c "
import socket
socket.create_connection(('127.0.0.1', $UPSTREAM_PORT), timeout=0.5).close()
" >/dev/null 2>&1; then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 0.3
done
if [ "$ready" -ne 1 ]; then
    echo "FAIL: fake upstream server never became ready"
    echo "--- process check ---"
    kill -0 "$UPSTREAM_PID" 2>&1 && echo "pid $UPSTREAM_PID is alive" || echo "pid $UPSTREAM_PID is dead"
    exit 1
fi
sleep 0.3   # small safety margin between "socket accepting" and "fully serving"

export CERTMGR_CHALLENGE_PROXY_UPSTREAM_HOST="127.0.0.1"
export CERTMGR_CHALLENGE_PROXY_UPSTREAM_PORT="$UPSTREAM_PORT"

pass=0
fail=0

run_case() {
    desc="$1"; method="$2"; path_info="$3"; expect_status="$4"

    export REQUEST_METHOD="$method"
    export PATH_INFO="$path_info"

    "$CGI" >/tmp/proxy_stdout 2>/tmp/proxy_stderr || true
    actual_status="$(head -n1 /tmp/proxy_stdout | sed -n 's/^Status: \([0-9]*\).*/\1/p')"

    if [ "$actual_status" = "$expect_status" ]; then
        echo "PASS: $desc"
        pass=$((pass + 1))
    else
        echo "FAIL: $desc (expected status $expect_status, got '$actual_status')"
        echo "  method:    $method"
        echo "  path_info: $path_info"
        echo "  output:    $(cat /tmp/proxy_stdout)"
        echo "  stderr:    $(cat /tmp/proxy_stderr 2>/dev/null)"
        fail=$((fail + 1))
    fi
}

run_case "valid token, upstream has it" GET "/$VALID_TOKEN" 200

export REQUEST_METHOD="GET"
export PATH_INFO="/$VALID_TOKEN"
"$CGI" > /tmp/proxy_stdout 2>/tmp/proxy_stderr || true
body="$(sed -n '/^\r\{0,1\}$/,$p' /tmp/proxy_stdout | tail -n +2)"
if [ "$body" = "$VALIDATION" ]; then
    echo "PASS: response body matches upstream content exactly"
    pass=$((pass + 1))
else
    echo "FAIL: response body mismatch: got '$body'"
    fail=$((fail + 1))
fi

run_case "valid-shaped token, upstream doesn't have it" GET "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" 404
run_case "path traversal in token" GET "/../../../etc/passwd" 400
run_case "empty token" GET "/" 400
run_case "token too short" GET "/short" 400
run_case "token with shell metacharacters" GET "/aaaaaaaaaaaaaaaaaaaaaaaaa;rm -rf /" 400
run_case "wrong HTTP method" POST "/$VALID_TOKEN" 405

echo
echo "----------------------------------------"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
