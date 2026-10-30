#!/usr/bin/env bash
# Securely rotate the Aliyun RAM AccessKey used by the broker on ECS.
#
# Preferred interactive usage:
#   sudo bash scripts/broker/inject-aliyun-ak.sh
#
# Non-interactive automation may provide ALIYUN_ACCESS_KEY and
# ALIYUN_ACCESS_SECRET as environment variables. Never edit this tracked file
# to insert real credentials, pass the secret as a command-line argument, or
# paste it into an AI/chat session.

set -euo pipefail
set +x
umask 077

BROKER_ROOT="${BROKER_ROOT:-/opt/secret-broker}"
cd "$BROKER_ROOT"

if [[ -z "${ALIYUN_ACCESS_KEY:-}" || -z "${ALIYUN_ACCESS_SECRET:-}" ]]; then
  if [[ ! -t 0 ]]; then
    echo "ERROR: non-interactive use requires ALIYUN_ACCESS_KEY and ALIYUN_ACCESS_SECRET" >&2
    exit 2
  fi
  if [[ -z "${ALIYUN_ACCESS_KEY:-}" ]]; then
    read -r -p "Aliyun AccessKey ID: " ALIYUN_ACCESS_KEY
  fi
  if [[ -z "${ALIYUN_ACCESS_SECRET:-}" ]]; then
    read -r -s -p "Aliyun AccessKey Secret: " ALIYUN_ACCESS_SECRET
    printf '\n'
  fi
fi

if [[ ! "$ALIYUN_ACCESS_KEY" =~ ^LTAI[A-Za-z0-9]{12,}$ ]]; then
  echo "ERROR: ALIYUN_ACCESS_KEY does not match the expected LTAI format" >&2
  exit 2
fi
if (( ${#ALIYUN_ACCESS_SECRET} < 16 )); then
  echo "ERROR: ALIYUN_ACCESS_SECRET is unexpectedly short" >&2
  exit 2
fi

export SOPS_AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-$BROKER_ROOT/age/key.txt}"
[[ -r "$SOPS_AGE_KEY_FILE" ]] || {
  echo "ERROR: SOPS age key is not readable: $SOPS_AGE_KEY_FILE" >&2
  exit 1
}
[[ -f secrets/common.env ]] || {
  echo "ERROR: encrypted secrets/common.env does not exist" >&2
  exit 1
}

TMP_DIR=$(mktemp -d "secrets/.inject-aliyun.XXXXXX")
chmod 700 "$TMP_DIR"
AK_FILE="$TMP_DIR/access-key-id"
SECRET_FILE="$TMP_DIR/access-key-secret"
PLAIN_FILE="$TMP_DIR/common.plain.env"
NEW_FILE="$TMP_DIR/common.env"
NEXT_FILE="secrets/.common.env.next.$$"

secure_remove() {
  local target
  for target in "$AK_FILE" "$SECRET_FILE" "$PLAIN_FILE" "$NEW_FILE" "$NEXT_FILE"; do
    [[ -e "$target" ]] || continue
    if command -v shred >/dev/null 2>&1; then
      shred -u -- "$target" 2>/dev/null || rm -f -- "$target"
    else
      rm -f -- "$target"
    fi
  done
  rmdir "$TMP_DIR" 2>/dev/null || true
  unset ALIYUN_ACCESS_SECRET ALIYUN_ACCESS_KEY
}
trap secure_remove EXIT HUP INT TERM

printf '%s\n' "$ALIYUN_ACCESS_KEY" > "$AK_FILE"
printf '%s\n' "$ALIYUN_ACCESS_SECRET" > "$SECRET_FILE"
chmod 600 "$AK_FILE" "$SECRET_FILE"

sops --decrypt secrets/common.env > "$PLAIN_FILE"
chmod 600 "$PLAIN_FILE"

# Read credential values from protected files rather than argv, then replace or
# append the two fields while preserving all unrelated entries.
awk -v ak_file="$AK_FILE" -v secret_file="$SECRET_FILE" '
  BEGIN {
    if ((getline ak < ak_file) <= 0) exit 20
    close(ak_file)
    if ((getline sk < secret_file) <= 0) exit 21
    close(secret_file)
    seen_ak = 0
    seen_sk = 0
  }
  /^ALIYUN_ACCESS_KEY=/ {
    print "ALIYUN_ACCESS_KEY=" ak
    seen_ak = 1
    next
  }
  /^ALIYUN_ACCESS_SECRET=/ {
    print "ALIYUN_ACCESS_SECRET=" sk
    seen_sk = 1
    next
  }
  { print }
  END {
    if (!seen_ak) print "ALIYUN_ACCESS_KEY=" ak
    if (!seen_sk) print "ALIYUN_ACCESS_SECRET=" sk
  }
' "$PLAIN_FILE" > "$NEW_FILE"
chmod 600 "$NEW_FILE"

# Encrypt before moving into place. The final rename occurs inside secrets/ so
# readers never observe a partially written credential file.
sops --encrypt --in-place "$NEW_FILE"
install -m 600 "$NEW_FILE" "$NEXT_FILE"
mv -f -- "$NEXT_FILE" secrets/common.env

systemctl restart secret-broker
systemctl is-active --quiet secret-broker

# Verify only field presence; never print decrypted values.
if sops --decrypt secrets/common.env | awk -F= '
  /^ALIYUN_ACCESS_KEY=.+/ { have_ak = 1 }
  /^ALIYUN_ACCESS_SECRET=.+/ { have_secret = 1 }
  END { exit !(have_ak && have_secret) }
'; then
  echo "Aliyun credentials rotated; encrypted fields are present and secret-broker is active."
else
  echo "ERROR: post-rotation verification failed" >&2
  exit 1
fi
