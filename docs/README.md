# Documentation

This folder explains the FortiGate CIS Compliance Checker from three
angles: how to set it up, how it works, and what each check means.

## Start here

| If you want to… | Read |
|---|---|
| Understand what the tool is and see example output | [Project README](../README.md) |
| Create the read-only account the scanner uses | [setup_readonly_user.md](setup_readonly_user.md) |
| Understand how a scan runs and what the results mean | [how-it-works.md](how-it-works.md) |
| Look up one check: why it matters, how it is tested, how to fix it | [checks-reference.md](checks-reference.md) |
| Use the Apply / Undo console to fix failed checks | [fix-console.md](fix-console.md) and [setup_write_user.md](setup_write_user.md) |
| Work out why a scan failed or a result looks wrong | [troubleshooting.md](troubleshooting.md) |

## Suggested reading order

1. Project README, to see what the tool does.
2. `setup_readonly_user.md`, then run your first scan.
3. `how-it-works.md`, to understand the report you got.
4. `checks-reference.md`, as a lookup while you work through failures.
5. `fix-console.md` only if you want automatic fixes.

## Glossary

| Term | Meaning |
|---|---|
| **FortiGate** | Fortinet's firewall appliance (hardware or VM) running FortiOS. |
| **FortiOS** | The operating system on a FortiGate. This tool targets 7.x. |
| **CIS Benchmark** | A published list of security hardening recommendations. The checks here are modelled on the FortiGate 7.x benchmark but written independently. |
| **Level 1 / Level 2** | CIS grading. Level 1 is baseline hardening with little operational cost. Level 2 is stricter and may affect usability. |
| **REST API** | The HTTPS interface the scanner uses to read configuration. |
| **API token** | A secret key that identifies an API user. Sent as a `Bearer` header. |
| **Access profile** | A FortiGate permission set. Each group (system, network, firewall…) is `none`, `read` or `read-write`. |
| **Trusthost** | A source IP address a user or token may connect from. Requests from elsewhere are refused. |
| **CMDB** | The FortiGate configuration database. The REST API exposes it under `/api/v2/cmdb`. |
| **VDOM** | Virtual domain: a virtual firewall inside one FortiGate. The default is `root`. |
| **Remediation** | The FortiOS commands that bring a failed check into compliance. |
