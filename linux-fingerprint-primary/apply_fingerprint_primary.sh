#!/usr/bin/env bash
#
# apply_fingerprint_primary.sh
#
# Switches Remote-Unlock from a TRUE SECOND FACTOR (password always
# required, phone is an extra check on top — `optional`) to a
# FINGERPRINT-PRIMARY / PASSWORD-FALLBACK model (phone succeeds -> no
# password needed at all; phone fails or times out -> normal password
# prompt appears instead). This matches the Windows Credential Provider
# behavior in windows/README-Windows.md exactly: one factor is ever
# actually required, not both.
#
# What changes: only the PAM keyword, `optional` -> `sufficient`, on the
# pam_exec.so line for pam_unlock_helper.py. No changes to
# pam_unlock_helper.py or listener.py are needed — their exit-code
# contract (0 = phone approved, 1 = anything else) already means exactly
# what `sufficient` needs it to mean.
#
# PAM ordering rule this depends on: this line must come BEFORE the
# distro's normal pam_unix.so password line in the same file, so that a
# phone success is evaluated first and can short-circuit the password
# prompt; a phone failure/timeout falls through to pam_unix.so
# afterwards, same as today.
#
# Safety: this script backs up the target file, and refuses to run
# unless a `pam_unlock_helper.py` reference already exists in it (i.e.
# you've already done the original setup) — it never adds the pam_exec
# line from scratch. Test on a SEPARATE virtual terminal or a `sudo -k;
# sudo true` prompt BEFORE trusting it on your graphical login screen.
#
set -euo pipefail

TARGET="${1:-/etc/pam.d/sudo}"

if [[ ! -f "$TARGET" ]]; then
    echo "No such file: $TARGET" >&2
    exit 1
fi

if ! grep -q "pam_unlock_helper.py" "$TARGET"; then
    echo "No existing pam_unlock_helper.py line found in $TARGET." >&2
    echo "Run the original PAM setup step (README.md step 6) first —" >&2
    echo "this script only flips optional -> sufficient, it doesn't add the line." >&2
    exit 1
fi

if grep -qE '^\s*auth\s+sufficient\s+pam_exec\.so\s+.*pam_unlock_helper\.py' "$TARGET"; then
    echo "Already set to 'sufficient' in $TARGET — nothing to do."
    exit 0
fi

backup="${TARGET}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$TARGET" "$backup"
echo "Backed up $TARGET -> $backup"

sed -i -E 's/^(\s*auth\s+)optional(\s+pam_exec\.so\s+.*pam_unlock_helper\.py.*)$/\1sufficient\2/' "$TARGET"

echo
echo "Changed 'optional' -> 'sufficient' for pam_unlock_helper.py in $TARGET"
echo
echo "TEST NOW, before closing this terminal:"
echo "  - Keep THIS terminal open and logged in."
echo "  - Open a SECOND terminal (or a new virtual console, Ctrl+Alt+F3) and try:"
echo "      sudo -k; sudo true"
echo "  - Confirm the phone-unlock flow works AND that cancelling/failing the"
echo "    phone prompt correctly falls back to a working password prompt."
echo "  - Only after both paths are confirmed, apply the same change to"
echo "    /etc/pam.d/gdm-password (or your display manager's PAM file) for"
echo "    graphical lock/login."
echo
echo "If anything goes wrong, restore with:"
echo "  sudo cp $backup $TARGET"
echo "or run revert_fingerprint_primary.sh $TARGET"
