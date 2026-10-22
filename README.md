# FortiGate CIS Compliance Checker

A small Python tool that audits a FortiGate firewall against hardening
controls modelled on the CIS FortiGate 7.x Benchmark. It only reads.
It writes a console summary, a CSV file and an HTML report, and each
failed check comes with the FortiOS commands that fix it.

Project page: https://error-siddh.github.io/fortigate_cis_checker/

Built for a security coursework project. This is not an official
CIS-CAT tool and does not contain any CIS benchmark text. Every check
was written independently.

---

## What it checks

| ID  | Level | Control                                                  |
|-----|-------|----------------------------------------------------------|
| 1.1 | 1     | Admin password minimum length is at least 14             |
| 1.2 | 1     | Admin lockout threshold (≤3) and duration (≥60 s) set    |
| 1.3 | 1     | Admin idle timeout is 5 minutes or less                  |
| 1.4 | 1     | No interface allows HTTP or Telnet for management        |
| 1.5 | 2     | Pre-login banner is enabled                              |
| 1.6 | 2     | USB auto-install of config and firmware is disabled      |
| 1.7 | 2     | Password complexity (upper, lower, digit, symbol)        |
| 1.8 | 1     | Default `admin` account is removed or trusthost-limited  |
| 2.1 | 1     | SNMP is disabled or v3-only (no v1/v2c communities)      |
| 2.2 | 1     | NTP synchronisation is enabled                           |
| 1.9 | 1     | `strong-crypto` is enabled                               |
| 1.10| 1     | HTTP admin requests are redirected to HTTPS              |
| 1.11| 1     | Admin HTTPS refuses TLS 1.0 and 1.1                      |
| 3.1 | 1     | Logs are sent to a remote syslog / FortiAnalyzer         |
| 3.2 | 1     | Every accept firewall policy logs traffic                |

Level 1 checks are baseline hardening. Level 2 checks are stricter.

## How it stays read-only

Two separate layers enforce it. Either one alone is enough to block
writes.

1. **In the client.** The REST client only sends `GET` requests. The
   SSH client only accepts commands from an allow-list (`get`, `show`,
   `diagnose sys`) and refuses everything else.
2. **On the device.** The API user is bound to an access profile where
   every permission group is set to `read`. The FortiGate itself refuses
   any write, even if the script were modified.

## Documentation

Full guides are in [`docs/`](docs/README.md): how a scan works, a
reference for every check (why it matters, how it is tested, how to
fix it), the Apply/Undo console, and troubleshooting.

## Layout

```
main.py         CLI entry point and orchestration
connector.py    REST API and SSH backends (read-only)
rules.py        The checks, one function per control
reporting.py    Console, CSV and HTML output
tests/          Mock "hardened" and "weak" configs for offline testing
docs/           Device-side setup guide and the GitHub Pages site
reports/        Sample reports from a real run
```

---

## Requirements

- Python 3.8 or newer (tested on 3.14)
- A FortiGate running FortiOS 7.x that you can reach over HTTPS
- Admin access to the FortiGate, needed once to create the read-only API user

## Installation

```bash
git clone https://github.com/ERROR-SIDDH/fortigate_cis_checker.git
cd fortigate_cis_checker
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## FortiGate setup (one time)

Log in to the FortiGate CLI as a full admin and run the steps below.
[`docs/setup_readonly_user.md`](docs/setup_readonly_user.md) has the
longer version, including the SSH backend.

**1. Create a read-only access profile.**

```
config system accprofile
    edit "cis_readonly"
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
        set wanoptgrp read
        set wifi read
    next
end
```

**2. Create a REST API user bound to that profile.** Set the trusthost
to the IP of the machine that will run the checker. On Linux, `ip addr`
shows it.

```
config system api-user
    edit "cis_checker_api"
        set accprofile "cis_readonly"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost <scanner-ip> 255.255.255.255
            next
        end
    next
end
```

**3. Generate the API token.** Run this from the top-level prompt, not
from inside a `config` block. FortiOS asks for the current admin
password and then prints the key once.

```
execute api-user generate-key cis_checker_api
```

Copy the key straight away, because FortiOS will not show it again.

## Usage

Pass the token through an environment variable so it stays out of your
shell history and out of the process list:

```bash
export FGT_API_TOKEN="<token from step 3>"
```

Then run the checker:

```bash
python3 main.py --backend api --host 172.20.80.130 --insecure --csv reports/report.csv --html reports/report.html
```

`--insecure` turns off TLS certificate checks. Only use it in a lab,
where the FortiGate is using its factory self-signed certificate.

### Options

| Flag              | Meaning                                              |
|-------------------|------------------------------------------------------|
| `--backend`       | `api` (recommended) or `ssh`                         |
| `--host`          | FortiGate management IP or hostname                  |
| `--port`          | Override the port (default 443 for api, 22 for ssh)  |
| `--vdom`          | VDOM to query, default `root`                        |
| `--token`         | API token (prefer the `FGT_API_TOKEN` env var)       |
| `--insecure`      | Skip TLS verification (lab only)                     |
| `--username`      | SSH username (SSH backend)                           |
| `--key-file`      | SSH private key (SSH backend)                        |
| `--csv` / `--html`| Where to write reports                               |
| `--level 1\|2`    | Only report checks at that CIS level                 |
| `--fail-on-warn`  | Exit 1 when any WARN result is present               |
| `-v`              | Verbose logging, including every HTTP request        |

Exit codes: `0` means every check passed, `1` means at least one
failed, `2` means the tool could not connect or log in.

---

## Results from a real run

These results come from a FortiGate VM (FortiOS 7.x) on a lab network.
It had the factory configuration plus a few password-policy changes.

```
====================================================================================================
FortiGate CIS Benchmark Compliance Check - 172.20.80.130
Generated: 2026-10-17T15:34:54.800357+00:00Z
====================================================================================================
[FAIL] 1.1    L1  Admin password minimum length enforced
        expected: enabled, >=14 chars
        actual  : status=enable, minimum-length=12
        fix     : config system password-policy ...
----------------------------------------------------------------------------------------------------
[PASS] 1.7    L2  Admin password policy enforces character-type complexity
        expected: all complexity minimums >=1
        actual  : min-lower-case-letter=1, min-upper-case-letter=1, min-number=1, min-non-alphanumeric=1
----------------------------------------------------------------------------------------------------
[PASS] 1.2    L1  Admin lockout threshold and duration configured
        expected: threshold<=3, duration>=60s
        actual  : threshold=3, duration=60s
----------------------------------------------------------------------------------------------------
[PASS] 1.3    L1  Administrative idle timeout set to <=5 minutes
        expected: <=5 minutes
        actual  : admintimeout=5 minutes
----------------------------------------------------------------------------------------------------
[FAIL] 1.4    L1  Only HTTPS/SSH (not HTTP/Telnet) permitted for admin access on interfaces
        expected: no interface allows http/telnet
        actual  : interfaces with http/telnet allowed: ['port1']
        fix     : config system interface ...
----------------------------------------------------------------------------------------------------
[PASS] 1.8    L1  Default 'admin' account renamed, disabled, or restricted by trusted hosts
        expected: 'admin' absent or trusthost-restricted
        actual  : no account named 'admin' exists
----------------------------------------------------------------------------------------------------
[FAIL] 1.5    L2  Pre-login administrative disclaimer/banner configured
        expected: enabled
        actual  : pre-login-banner=disable
        fix     : config system global ...
----------------------------------------------------------------------------------------------------
[FAIL] 1.6    L2  Auto-install of configuration/firmware from USB is disabled
        expected: both disabled
        actual  : auto-install-config=enable, auto-install-image=enable
        fix     : config system auto-install ...
----------------------------------------------------------------------------------------------------
[PASS] 2.1    L1  SNMP restricted to v3 (no v1/v2c communities), or disabled
        expected: disabled or v3-only
        actual  : snmp_enabled=False, v1/v2c_communities=0
----------------------------------------------------------------------------------------------------
[PASS] 2.2    L1  NTP synchronization enabled (accurate log timestamps)
        expected: ntpsync enabled
        actual  : ntpsync=enable
----------------------------------------------------------------------------------------------------
[FAIL] 3.1    L1  Event logging enabled to a remote target (FortiAnalyzer/syslog)
        expected: remote logging enabled with server set
        actual  : status=disable, server=unset
        fix     : config log syslogd setting ...
----------------------------------------------------------------------------------------------------
Summary: 6 PASS, 5 FAIL, 0 WARN, 0 ERROR out of 11 checks  |  Compliance score: 54.5%
====================================================================================================
```

The full reports are in [`reports/report.html`](reports/report.html)
and [`reports/report.csv`](reports/report.csv).

### What failed and how to fix it

| ID  | Finding                                   | Fix (FortiOS CLI)                                                                  |
|-----|-------------------------------------------|------------------------------------------------------------------------------------|
| 1.1 | Minimum password length is 12             | `config system password-policy` → `set minimum-length 14`                         |
| 1.4 | `port1` allows HTTP and/or Telnet         | `config system interface` → `edit port1` → `set allowaccess https ssh`             |
| 1.5 | No pre-login banner                       | `config system global` → `set pre-login-banner enable`                             |
| 1.6 | USB auto-install is enabled               | `config system auto-install` → `set auto-install-config disable`, `set auto-install-image disable` |
| 3.1 | No remote logging                         | `config log syslogd setting` → `set status enable`, `set server <ip>`              |

Most of these are factory defaults, which is the main finding of the
project: a FortiGate fresh out of the box does not meet the CIS
baseline. Apply the fixes, run the checker again, and the score goes up.

---

## Testing without a firewall

`tests/test_rules_mock.py` runs every rule against two made-up
configurations. One is fully hardened and the other is deliberately
weak. Run it from the folder that contains the project:

```bash
cd ..
python3 -m fortigate_cis_checker.tests.test_rules_mock
```

It prints both reports and writes `reports/demo_hardened.html` and
`reports/demo_weak.html`. If you have pytest installed, `pytest tests/`
runs the same file as assertions.

## Troubleshooting

These are the errors that came up while setting this up, and what fixed
each one.

| Symptom | Cause | Fix |
|---|---|---|
| `Could not find api-user cis_readonly` | You created a normal admin or the profile, not an API user | Create a `config system api-user` entry (step 2) |
| `Unknown action 0` on `execute api-user generate-key` | You ran it from inside a `config` block | Type `end` until you are back at the `#` prompt, then run it again |
| `CERTIFICATE_VERIFY_FAILED` | The FortiGate is using its self-signed certificate | Add `--insecure` in a lab, or install a trusted certificate |
| `Authentication failed (401)` | The trusthost does not match the scanner's IP, or the token is wrong | Check `ip addr` on the scanner and update `ipv4-trusthost` |
| `attempted relative import` | An old version of `main.py` | Pull the latest code; `python3 main.py` now works directly |

## Adding a check

Each rule in `rules.py` is a function that takes a `RuleContext` and
returns a `RuleResult`. Copy an existing rule, change the CMDB path and
the condition, and add the function to `ALL_RULES`. FortiOS REST paths
put a dot between nested tables, for example `/system.snmp/sysinfo` and
`/log.syslogd/setting`. A slash there makes the API return HTTP 400.

## Notes for the write-up

- When citing the official CIS FortiGate Benchmark, give its exact
  version. Section numbers change between revisions, so map each rule
  ID here to the section in the version you cite.
- The two read-only layers are an example of defence in depth: neither
  layer has to be trusted on its own.
- The CSV and HTML reports can serve as evidence for the compliance
  report.
- After the assessment, rotate or delete the API token
  (`config system api-user` → `delete cis_checker_api`).

