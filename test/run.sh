#!/usr/bin/env bash
#
# End-to-end test: a real OpenVPN server loads vpynauth.so with sample/vpyn.py, and
# OpenVPN clients try to log in with good and bad credentials.
#
# Runs unprivileged inside a user + network namespace, so it needs openvpn, openssl,
# unshare, unprivileged user namespaces and /dev/net/tun. Set KEEP=1 to keep the logs.

set -euo pipefail

TEST=$(cd "$(dirname "$0")" && pwd)
REPO=$(dirname "$TEST")

if [[ "${1:-}" != --inside ]]; then
    make -s -C "$REPO"
    exec unshare --map-root-user --net "$0" --inside
fi

WORK=$(mktemp -d)
cleanup() {
    kill $(jobs -p) 2>/dev/null || true
    wait 2>/dev/null || true
    if [[ -n "${KEEP:-}" ]]; then echo "logs kept in $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
cd "$WORK"

ip link set lo up

# throwaway PKI: a CA, the server, and two clients ("test" matches the sample user, "other" doesn't)

mkdir pki
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=vpynauth-test-ca -keyout pki/ca.key -out pki/ca.crt 2>/dev/null

issue() {
    local name=$1 eku=$2
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -subj "/CN=$name" -keyout "pki/$name.key" -out "pki/$name.csr" 2>/dev/null
    openssl x509 -req -in "pki/$name.csr" -CA pki/ca.crt -CAkey pki/ca.key -CAcreateserial -days 1 \
        -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=%s\n' "$eku") \
        -out "pki/$name.crt" 2>/dev/null
}
issue server serverAuth
issue test   clientAuth
issue other  clientAuth
issue alice  clientAuth

# run the plugin against a copy of the sample so the test can add users to it

cp -r "$REPO/sample" sample

# wait_for <file> <count> <pattern> [pid]: until pattern appears count times, or pid exits

wait_for() {
    local file=$1 count=$2 pattern=$3 pid=${4:-}
    for _ in $(seq 100); do
        (( $(grep -c -- "$pattern" "$file" 2>/dev/null || true) >= count )) && return 0
        [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null && return 1
        sleep 0.2
    done
    return 1
}

openvpn --cd "$WORK" --config "$TEST/server.conf" \
    --plugin "$REPO/vpynauth.so" "$WORK/sample" vpyn > server.log 2>&1 &
SERVER=$!
STARTS=1

if ! wait_for server.log 1 'Initialization Sequence Completed' $SERVER; then
    echo "FAIL: server did not start"; cat server.log; exit 1
fi

FAILED=0

# scenario <name> <ACCEPT|REJECT> <cert> <username> <password>

scenario() {
    local name=$1 expect=$2 cert=$3 user=$4 pass=$5
    local log="client-$name.log"

    printf '%s\n%s\n' "$user" "$pass" > "creds-$name"
    openvpn --cd "$WORK" --config "$TEST/client.conf" --cert "pki/$cert.crt" --key "pki/$cert.key" \
        --auth-user-pass "creds-$name" > "$log" 2>&1 &
    local client=$!

    local got=TIMEOUT
    for _ in $(seq 100); do
        if grep -q 'Initialization Sequence Completed' "$log"; then got=ACCEPT; break; fi
        if grep -q 'AUTH_FAILED' "$log"; then got=REJECT; break; fi
        kill -0 $client 2>/dev/null || { got=EXITED; break; }
        sleep 0.2
    done
    kill $client 2>/dev/null || true
    wait $client 2>/dev/null || true

    if [[ $got == "$expect" ]]; then
        printf 'PASS  %-22s %s\n' "$name" "$got"
    else
        printf 'FAIL  %-22s expected %s, got %s\n' "$name" "$expect" "$got"
        sed 's/^/    client: /' "$log" | tail -15
        FAILED=1
    fi
}

scenario good           ACCEPT test  test  test
scenario wrong-password REJECT test  test  nope
scenario unknown-user   REJECT test  bob   test
scenario cn-mismatch    REJECT other test  test

# users are read when the plugin opens, so a new user needs a reload

PYTHONDONTWRITEBYTECODE=1 python3 -c "
import sys; sys.path.insert(0, 'sample')
from vpyn import hash_password
print('alice,' + hash_password(b'alice'))" >> sample/users

scenario new-user-before-hup REJECT alice alice alice

# SIGHUP makes OpenVPN close and reopen its plugins; the script is re-imported

kill -HUP $SERVER
STARTS=$((STARTS + 1))
if wait_for server.log $STARTS 'Initialization Sequence Completed' $SERVER; then
    scenario after-hup          ACCEPT test  test  test
    scenario new-user-after-hup ACCEPT alice alice alice
else
    echo "FAIL  sighup                 server did not restart"
    FAILED=1
fi

# the server log must show the plugin's own lines and no Python errors

if ! grep -q 'Connection from: 127.0.0.1 .* test' server.log; then
    echo "FAIL  server log is missing the sample's 'Connection from' line"
    FAILED=1
fi
if grep -qE 'Traceback|vpynauth: ERROR' server.log; then
    echo "FAIL  server log contains Python or plugin errors"
    FAILED=1
fi

if (( FAILED )); then
    sed 's/^/    server: /' server.log | tail -40
    exit 1
fi
echo "all passed"
