# Troubleshooting

Start with the exact message. The scanner exits with code `2` when it
cannot connect or authenticate.

## Connection and authentication

| Symptom | Likely cause | Fix |
|---|---|---|
| `Authentication failed (401)` | Wrong or stale token, token not exported in this shell, **or** the request comes from an IP not in the user's trusthost | Check with `curl` (below). Re-export the token. Confirm the trusthost matches the address the FortiGate sees. |
| `Forbidden (403)` for a path | The access profile has no read access to that table | Give the profile `read` for the relevant group (see setup guide). |
| `Could not connect` | Wrong host or port, admin HTTPS port is not 443, firewall in the way | Check `--host`, `--port`, and that HTTPS admin access is allowed from your machine. |
| `TLS/SSL error` | Self-signed certificate | Install a trusted certificate, or use `--insecure` in a lab only. |
| `Timed out` | Network path blocked or device overloaded | Test with `ping` and a browser to the GUI. |
| `no API token provided` | Neither `--token` nor `FGT_API_TOKEN` set | `export FGT_API_TOKEN=...` in the same shell. |
| `SSH connection failed` | Wrong credentials or key, SSH not allowed on the interface | Test `ssh user@host` manually. |
| `Refusing to send non-read-only command` | A check tried a command outside the allow-list | A bug in a custom rule; the allow-list is `get`, `show`, `diagnose sys`, `diagnose debug`. |

### Test a token without running the tool

```bash
curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $FGT_API_TOKEN" \
  "https://<firewall-ip>/api/v2/monitor/system/status"
```

`200` means the token works. `401` means token or trusthost is wrong.
This prints only the status code, never the token.

### Which address does the FortiGate see?

The trusthost must be the address the request arrives from, which can
differ from your machine's own address when you use a VPN or NAT. If
unsure, check the FortiGate login log for your last successful admin
login and use that source IP.

### Lost the token

A token cannot be shown again. Generate a new one; the old one stops
working:

```
execute api-user generate-key cis_checker_api
```

## Results that look wrong

| Symptom | Explanation |
|---|---|
| A check shows `ERROR` | The scanner could not read what it needed. Read the *Actual* text; it contains the cause (often a 403 or a missing table). |
| A table returns nothing (404) | The feature is absent on this model or licence. The scanner treats it as "not configured", which can make a check pass or fail depending on the rule. |
| Value shows `unset` | The setting is not present in the API response. On some FortiOS versions a default value is omitted. |
| 1.7 shows `WARN` | By design: complexity is a policy choice, not a hard fail. |
| Check 3.2 passes with zero policies | There was nothing to fail. |
| Score differs from last run | You changed settings, or the tool gained new checks. Compare check by check using the CSV. |
| `--level 1` run lists fewer checks | Expected: the filter keeps only checks of that level. |
| VDOM-specific data missing | Pass `--vdom <name>`; the default is `root`. |

## Fix console

| Symptom | Fix |
|---|---|
| `ERROR: set FGT_WRITE_TOKEN` | Export both tokens before starting `webui.py`. |
| All checks `ERROR` with 401 | The **read** token is the problem, not the write token. |
| Apply fails with `PUT … 403` | The write profile lacks `sysgrp read-write`. |
| Apply fails with `PUT … 400` or `500` | The device rejected the value; keep the error text and apply the remediation manually. |
| Undo button missing | No snapshot exists for that check (never applied, or `undo_state.json` was deleted). |
| Lost admin GUI access after Apply | You tightened 1.10 or 1.11. Use SSH or console to reverse it (`set admin-https-ssl-versions tlsv1-1 tlsv1-2 tlsv1-3`). |
| Port in use | Use `--listen-port <other>`. |

## Still stuck

Run with `-v` to log every HTTP request and re-run one check at a time
from Python:

```python
from connector import FortiGateAPIClient
c = FortiGateAPIClient("<firewall-ip>", "<token>", verify_ssl=False)
print(c.cmdb("/system/global"))
```

Open an issue on GitHub with the *Actual* text of the failing check and
your FortiOS version. Never paste tokens or passwords.
