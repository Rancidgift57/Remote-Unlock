# Linux: switching from second factor to fingerprint-primary

By default, the upstream project's `/etc/pam.d/...` line is:

```
auth optional pam_exec.so /home/YOURUSER/remote-unlock/pam_unlock_helper.py
```

`optional` = **true second factor**: your password is always required
regardless of what the phone does; a phone success adds nothing on its
own, a phone failure doesn't block you either (that's what "optional"
means in PAM terms) — its only effect in this stack is a checkbox that
can't independently deny or grant.

To match the Windows Credential Provider behavior — **fingerprint is the
lock, password is the fallback only if fingerprint fails** — change the
keyword to `sufficient`:

```
auth sufficient pam_exec.so /home/YOURUSER/remote-unlock/pam_unlock_helper.py
```

## Why no Python changes are needed

`pam_unlock_helper.py`'s contract was already written to support this:
exit `0` only on a verified phone success, exit `1` on literally anything
else (timeout, malformed signal, socket error — see its docstring). That
is precisely what `sufficient` needs: success short-circuits the rest of
the auth stack (you're in, no password prompt), failure falls through to
the next module in the stack — normally `pam_unix.so`, your normal
password check — which then prompts you as usual.

`listener.py` needs no changes either — it already only signals `1`
(success) after full nonce/signature/rate-limit verification, and `0`
otherwise.

## How to apply it

```bash
chmod +x apply_fingerprint_primary.sh revert_fingerprint_primary.sh

# sudo prompts first (safest place to test):
sudo ./apply_fingerprint_primary.sh /etc/pam.d/sudo

# test in a SECOND terminal before touching anything else:
sudo -k; sudo true

# only once that works both ways (phone succeeds -> no password;
# phone fails/cancelled -> normal password prompt appears), apply the
# same change to your display manager's PAM file for the lock/login
# screen, e.g.:
sudo ./apply_fingerprint_primary.sh /etc/pam.d/gdm-password
```

To go back to true second-factor (password always required) at any time:

```bash
sudo ./revert_fingerprint_primary.sh /etc/pam.d/sudo
sudo ./revert_fingerprint_primary.sh /etc/pam.d/gdm-password
```

## Ordering matters

The `pam_exec.so` line must come **before** the distro's normal
`pam_unix.so` password line in the same file. That's already the
convention the upstream README's step 6 places it in — this change only
swaps the keyword, not the line's position. If you've reordered the file
yourself, put the fingerprint line back above the password line before
applying `sufficient`, or a phone failure won't correctly fall through to
a password prompt.

## Same tradeoff as Windows, stated plainly

This is a real reduction in security compared to the original
second-factor design, not just a config tweak: **phone-key compromise
now becomes full account compromise on its own**, with no password check
in the loop when the phone succeeds. The upstream README already says
this explicitly under step 6 ("if you deliberately want passwordless
phone-only login, understand exactly what you're trading away") — this
doc is just making that switch concrete and reversible, not arguing you
into or out of it.
