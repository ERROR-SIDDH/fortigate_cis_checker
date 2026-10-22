# Fix console (Apply and Undo)

The scanner only reads. The fix console is an **optional, separate**
tool that changes the settings behind failed checks, and can put them
back.

> **Use it on a lab or test device first.** Applying fixes changes a
> live firewall. Some fixes can reduce your own access (see
> [Lockout risks](#lockout-risks)).

## What it is

`webui.py` starts a small web server on `127.0.0.1` (your machine only).
Open it in a browser to:

1. Scan the FortiGate with the **read** token and see every result.
2. Click **Apply fix** on a failed check to write the compliant value
   with the **write** token.
3. Click **Undo** to restore the exact value that was there before.

## Two tokens, on purpose

| | Read token | Write token |
|---|---|---|
| Environment variable | `FGT_API_TOKEN` | `FGT_WRITE_TOKEN` |
| FortiGate user | `cis_checker_api` | `cis_fixer_api` |
| Access profile | every group `read` | `sysgrp read-write`, others `read` |
| Used for | scanning | Apply and Undo only |

The scanner code never receives the write token. Setup steps for the
write user are in [setup_write_user.md](setup_write_user.md). Delete that
user when you are finished.

## Running it

```bash
export FGT_API_TOKEN="<read-only token>"
export FGT_WRITE_TOKEN="<read-write token>"
python3 webui.py --host <firewall-ip> --insecure
```

Then open `http://127.0.0.1:8080`. Use `--listen-port` to change the
port and `--vdom` for a VDOM other than `root`. `--insecure` skips TLS
verification and is for labs with the factory self-signed certificate.

## How Apply and Undo work

**Apply** for a check:

1. Reads the current values of the settings it will change.
2. Saves them to `undo_state.json`, but only if no earlier snapshot for
   that check exists. Applying twice therefore never overwrites the
   original value with an already-fixed one.
3. Sends a `PUT` to the matching CMDB table with the compliant values.

**Undo** sends a `PUT` with the saved values, then deletes the snapshot.

Example for check 1.3 when the idle timeout was 30:

```
Apply  →  saves {"admintimeout": 30}   writes {"admintimeout": 5}
Undo   →  writes {"admintimeout": 30}  removes the snapshot
```

`undo_state.json` is created next to `fixer.py`, is git-ignored, and
holds configuration values (not secrets).

## What it can fix

Checks 1.1, 1.2, 1.3, 1.5, 1.6, 1.9, 1.10, 1.11, 1.12, 1.13, 1.14, 1.15
and 2.2. These are single-table settings. See `FIXES` in `fixer.py`.

It deliberately does **not** fix 1.4, 1.7, 1.8, 2.1, 3.1 or 3.2. They
need per-object edits (interfaces, admins, policies), values only you
know (a syslog server), or a policy decision. Use the remediation
commands shown for those checks.

## Lockout risks

| Fix | Risk |
|---|---|
| 1.2 lockout | Repeated wrong passwords now lock the account for a minute. |
| 1.3 idle timeout | Sessions end after 5 idle minutes. |
| 1.10 / 1.11 | Old browsers or scripts using HTTP or TLS 1.0/1.1 lose admin access. |
| 1.12 maintainer | Removes a password-recovery route; keep another one. |
| 1.15 SCP | Backups taken over SCP stop working. |

Keep an SSH or console session open while testing so you can reverse a
change.

## Safety properties

- Listens on `127.0.0.1` only; it is not reachable from the network.
- Every Apply/Undo request must carry a custom header that a web page on
  another site cannot add without permission, which blocks cross-site
  request forgery.
- Fixes are limited to the allow-list in `FIXES`; any other ID is rejected.

## Limitations

- REST only; there is no SSH write path.
- Undo state is local to the machine and file. If you delete
  `undo_state.json` you lose the ability to undo.
- Applying a fix does not re-verify the result itself; the page rescans
  automatically so you can see whether the check now passes.
- No multi-user login: anyone on your machine who can reach the port can
  click the buttons.
