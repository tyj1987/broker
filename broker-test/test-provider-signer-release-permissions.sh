#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo 'test must run as root' >&2; exit 1; }
for command in setfacl runuser useradd userdel; do
  command -v "$command" >/dev/null || { echo "missing test dependency: $command" >&2; exit 1; }
done

readonly TEST_ROOT="$(mktemp -d)"
readonly GITHUB_USER="broker-test-github-$$"
readonly ALIYUN_USER="broker-test-aliyun-$$"
cleanup() {
  userdel "$GITHUB_USER" >/dev/null 2>&1 || true
  userdel "$ALIYUN_USER" >/dev/null 2>&1 || true
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

useradd --system --no-create-home --shell /usr/sbin/nologin "$GITHUB_USER"
useradd --system --no-create-home --shell /usr/sbin/nologin "$ALIYUN_USER"
install -d -o root -g root -m 0550 "$TEST_ROOT/releases/release/bin"
install -o root -g root -m 0550 /bin/true "$TEST_ROOT/releases/release/bin/github-signer"
install -o root -g root -m 0550 /bin/true "$TEST_ROOT/releases/release/bin/aliyun-signer"
install -o root -g root -m 0440 /etc/hosts "$TEST_ROOT/releases/release/bin/private-runtime"

for directory in "$TEST_ROOT" "$TEST_ROOT/releases" "$TEST_ROOT/releases/release" "$TEST_ROOT/releases/release/bin"; do
  setfacl -m "u:$GITHUB_USER:--x,u:$ALIYUN_USER:--x,m::r-x" "$directory"
done
setfacl -m "u:$GITHUB_USER:r-x,m::r-x" "$TEST_ROOT/releases/release/bin/github-signer"
setfacl -m "u:$ALIYUN_USER:r-x,m::r-x" "$TEST_ROOT/releases/release/bin/aliyun-signer"
if [[ "${BROKER_TEST_OPEN_CROSS_ACCESS:-0}" == 1 ]]; then
  setfacl -m "u:$GITHUB_USER:r-x,m::r-x" "$TEST_ROOT/releases/release/bin/aliyun-signer"
fi

deny() {
  if "$@"; then
    echo 'unexpected provider signer release access' >&2
    return 1
  fi
}

runuser -u "$GITHUB_USER" -- "$TEST_ROOT/releases/release/bin/github-signer"
runuser -u "$ALIYUN_USER" -- "$TEST_ROOT/releases/release/bin/aliyun-signer"
deny runuser -u "$GITHUB_USER" -- test -r "$TEST_ROOT/releases/release/bin/aliyun-signer"
deny runuser -u "$ALIYUN_USER" -- test -r "$TEST_ROOT/releases/release/bin/github-signer"
deny runuser -u "$GITHUB_USER" -- test -r "$TEST_ROOT/releases/release/bin/private-runtime"
deny runuser -u "$ALIYUN_USER" -- test -r "$TEST_ROOT/releases/release/bin/private-runtime"
deny runuser -u "$GITHUB_USER" -- ls "$TEST_ROOT/releases/release/bin"
deny runuser -u "$ALIYUN_USER" -- ls "$TEST_ROOT/releases/release/bin"

echo 'provider signer release ACLs: isolated execute-only traversal passed'
