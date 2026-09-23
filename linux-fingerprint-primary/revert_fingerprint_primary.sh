#!/usr/bin/env bash
#
# revert_fingerprint_primary.sh
#
# Restores the TRUE SECOND FACTOR model: password always required, phone
# is only ever an additional check. Flips `sufficient` back to `optional`
# for pam_unlock_helper.py. This is the escape hatch if fingerprint-primary
# mode causes problems.
#
set -euo pipefail

TARGET="${1:-/etc/pam.d/sudo}"

if [[ ! -f "$TARGET" ]]; then
    echo "No such file: $TARGET" >&2
    exit 1
fi

if ! grep -qE '^\s*auth\s+sufficient\s+pam_exec\.so\s+.*pam_unlock_helper\.py' "$TARGET"; then
    echo "No 'sufficient' pam_unlock_helper.py line found in $TARGET — nothing to revert."
    exit 0
fi

backup="${TARGET}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$TARGET" "$backup"
echo "Backed up $TARGET -> $backup"

sed -i -E 's/^(\s*auth\s+)sufficient(\s+pam_exec\.so\s+.*pam_unlock_helper\.py.*)$/\1optional\2/' "$TARGET"

echo "Changed 'sufficient' -> 'optional' for pam_unlock_helper.py in $TARGET"
echo "Password is now always required again; phone is back to being a second factor only."
