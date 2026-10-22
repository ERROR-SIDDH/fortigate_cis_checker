# How it works

## The scan in one picture

```
 you                 main.py              rules.py            FortiGate
  │  run command  ──►  │                    │                    │
  │                    │  build context  ──►│                    │
  │                    │   (api or ssh)     │                    │
  │                    │  for each rule  ──►│  read settings ───►│  GET /api/v2/cmdb/...
  │                    │                    │◄── JSON / text ────│  or: get / show ...
  │                    │◄─ RuleResult ──────│                    │
  │◄─ console, CSV, HTML report             │                    │
```

1. `main.py` parses the command line and connects. With `--backend api`
   it also makes one call to `/monitor/system/status` so a wrong host or
   token fails immediately with a clear message.
2. Every rule in `ALL_RULES` runs against a `RuleContext`. The context
   hides whether data comes from REST or SSH, and caches each table so a
   setting read by several checks is fetched once.
3. Each rule returns a `RuleResult`. A rule that crashes is turned into
   an `ERROR` result so one bad check never stops the run.
4. `reporting.py` writes the console summary, and optionally a CSV and a
   self-contained HTML file.

## The two backends

| | REST API (recommended) | SSH |
|---|---|---|
| Credential | API token | Username plus password or key |
| Data format | Structured JSON | CLI text parsed with regular expressions |
| Default port | 443 | 22 |
| Robustness | High: field names are stable | Lower: depends on CLI output layout |
| Allowed traffic | HTTP `GET` only | `get`, `show`, `diagnose sys`, `diagnose debug` |
| Used by the fix console | Yes (reads) | No |

Prefer the API. Use SSH only when you cannot create an API user.

## Reading a result

Each check produces:

| Field | Meaning |
|---|---|
| **ID** | Check number, such as `1.9`. Grouped by area: 1.x access and management, 2.x services, 3.x logging. |
| **Level** | CIS level, 1 or 2. |
| **Status** | `PASS`, `FAIL`, `WARN` or `ERROR` (below). |
| **Expected** | The condition needed to pass. |
| **Actual** | What the scanner found on your device. |
| **Remediation** | FortiOS commands that fix the problem. |

### Status values

| Status | Meaning | What to do |
|---|---|---|
| `PASS` | The setting meets the control. | Nothing. |
| `FAIL` | The setting does not meet the control. | Apply the remediation. |
| `WARN` | Present but weaker than the control, or needs human review. Today only check 1.7 returns it. | Review; tighten if your policy requires it. |
| `ERROR` | The scanner could not evaluate the check (permission, missing table, parse problem). | See [troubleshooting.md](troubleshooting.md). An error is not a pass. |

### Compliance score

`PASS count ÷ total checks`. `WARN` and `ERROR` count as not passing.
Use `--level 1` to score only baseline checks.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No check failed. |
| `1` | At least one `FAIL` (or a `WARN`, with `--fail-on-warn`). |
| `2` | Could not connect or authenticate. |

This makes the tool usable in a scheduled job or pipeline: a non-zero
exit means the device drifted from baseline.

## Output files

- **Console**: every check with expected, actual and fix, then a summary.
- **CSV** (`--csv`): one row per check, easy to filter in a spreadsheet.
- **HTML** (`--html`): a single file with no external resources, safe to
  email or attach. See [sample-report.html](sample-report.html).

## How read-only is enforced

Two independent layers (see the README for setup):

1. **Client.** The REST client only issues `GET`. The SSH client refuses
   any command that does not start with an allow-listed prefix.
2. **Device.** The scanner's account uses an access profile with every
   group set to `read`, so the FortiGate itself rejects writes.

Fixing configuration is a separate feature with its own token. See
[fix-console.md](fix-console.md).

## Adding your own check

1. Write `rule_<name>(ctx) -> RuleResult` in `rules.py`. For a single
   `config system global` value, call `_global_check(...)` as checks
   1.9–1.15 do. Handle both `ctx.backend == "api"` (use `ctx.cmdb(path)`)
   and SSH (use `ctx.cli("get ...")`).
2. Append it to `ALL_RULES` at the bottom of the file.
3. Add the setting to both mock configurations in
   `tests/test_rules_mock.py` (one passing, one failing).
4. Run the mock test (command in the README) and confirm the hardened
   config passes and the weak one fails.
5. Optional: add an entry to `FIXES` in `fixer.py` to give it an Apply
   button. Only single-table settings are suitable.

## Project layout

| File | Role |
|---|---|
| `main.py` | Command line, orchestration, exit codes |
| `connector.py` | Read-only REST and SSH clients |
| `rules.py` | One function per check, plus `ALL_RULES` |
| `reporting.py` | Console, CSV and HTML output |
| `fixer.py` | Optional write client with undo state |
| `webui.py` | Local Apply / Undo console |
| `tests/test_rules_mock.py` | Offline tests with hardened and weak configs |
