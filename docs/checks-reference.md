# Checks reference

One section per check. "API source" is the REST table the scanner reads
(under `/api/v2/cmdb`). "Auto-fix" means the [fix console](fix-console.md)
can apply and undo it.

Levels: **L1** baseline, **L2** stricter. Rule text is original wording
and is not taken from the CIS document; map IDs to your own benchmark
revision if you need to cite it.

| ID | L | Control | Auto-fix |
|---|---|---|---|
| [1.1](#11) | 1 | Minimum admin password length | yes |
| [1.2](#12) | 1 | Admin lockout | yes |
| [1.3](#13) | 1 | Admin idle timeout | yes |
| [1.4](#14) | 1 | No HTTP/Telnet management | no |
| [1.5](#15) | 2 | Pre-login banner | yes |
| [1.6](#16) | 2 | USB auto-install off | yes |
| [1.7](#17) | 2 | Password complexity | no |
| [1.8](#18) | 1 | Default `admin` restricted | no |
| [1.9](#19) | 1 | Strong crypto | yes |
| [1.10](#110) | 1 | HTTPS redirect | yes |
| [1.11](#111) | 1 | No TLS 1.0 / 1.1 for admin | yes |
| [1.12](#112) | 1 | Maintainer account off | yes |
| [1.13](#113) | 1 | Static-key ciphers off | yes |
| [1.14](#114) | 2 | Config backup on logout | yes |
| [1.15](#115) | 2 | Admin SCP off | yes |
| [2.1](#21) | 1 | SNMP disabled or v3-only | no |
| [2.2](#22) | 1 | NTP sync | yes |
| [3.1](#31) | 1 | Remote logging | no |
| [3.2](#32) | 1 | Policy traffic logging | no |

---

## 1.1
**Minimum admin password length.** *L1 · auto-fix*

- **Why:** short passwords fall quickly to guessing and brute force.
- **Source:** `/system/password-policy` (`status`, `minimum-length`). SSH: `get system password-policy`.
- **Pass:** policy enabled **and** minimum length ≥ 14.
- **Fix:** `config system password-policy` → `set status enable`, `set minimum-length 14`.
- **Note:** existing passwords are not rewritten; only new or changed ones are held to the rule.

## 1.2
**Admin lockout.** *L1 · auto-fix*

- **Why:** limits online password guessing against the admin login.
- **Source:** `/system/global` (`admin-lockout-threshold`, `admin-lockout-duration`).
- **Pass:** threshold between 1 and 3 **and** duration ≥ 60 seconds. A threshold of 0 (disabled) fails.
- **Fix:** `config system global` → `set admin-lockout-threshold 3`, `set admin-lockout-duration 60`.
- **Caution:** a legitimate admin who mistypes three times is locked out for a minute.

## 1.3
**Admin idle timeout.** *L1 · auto-fix*

- **Why:** an unattended logged-in session can be used by someone else.
- **Source:** `/system/global` (`admintimeout`, minutes).
- **Pass:** 1 to 5 minutes.
- **Fix:** `set admintimeout 5`.

## 1.4
**No HTTP or Telnet for management.** *L1 · manual*

- **Why:** both send credentials and sessions in clear text.
- **Source:** `/system/interface`, `allowaccess` on every interface.
- **Pass:** no interface lists `http` or `telnet`.
- **Fix:** per interface, `set allowaccess https ssh` (add `ping` if needed).
- **Why no auto-fix:** it edits individual interfaces, and removing access on the interface you are connected through locks you out. Do it deliberately.

## 1.5
**Pre-login banner.** *L2 · auto-fix*

- **Why:** a legal notice supports prosecution and sets expectations for authorised use.
- **Source:** `/system/global` (`pre-login-banner`).
- **Pass:** `enable`.
- **Fix:** `set pre-login-banner enable`. Customise the text with `config system replacemsg admin pre_admin-disclaimer-text`.
- **Note:** the auto-fix turns the banner on but does not write your wording.

## 1.6
**USB auto-install disabled.** *L2 · auto-fix*

- **Why:** a USB stick plugged into the device could load a configuration or firmware image without anyone logging in.
- **Source:** `/system/auto-install` (`auto-install-config`, `auto-install-image`).
- **Pass:** both `disable`.
- **Fix:** set both to `disable`.

## 1.7
**Password complexity.** *L2 · manual · can return WARN*

- **Why:** requiring mixed character types raises guessing cost.
- **Source:** `/system/password-policy` (`min-lower-case-letter`, `min-upper-case-letter`, `min-number`, `min-non-alphanumeric`).
- **Pass:** all four minimums ≥ 1. Otherwise `WARN`, not `FAIL`, because this is a policy choice some organisations make differently.
- **Fix:** set each minimum to 1.

## 1.8
**Default `admin` account restricted.** *L1 · manual*

- **Why:** `admin` is the first username every attacker tries.
- **Source:** `/system/admin`, the entry named `admin`.
- **Pass:** no account named `admin`, **or** `admin` has a `trusthost1` other than `0.0.0.0 0.0.0.0`.
- **Fix:** restrict `trusthost1` to your management subnet, or create a differently named admin and remove `admin`.
- **Limit:** only `trusthost1` is inspected, not `trusthost2` onward.

## 1.9
**Strong cryptography.** *L1 · auto-fix*

- **Why:** forces strong ciphers and protocol versions across services.
- **Source:** `/system/global` (`strong-crypto`).
- **Pass:** `enable`.
- **Caution:** very old clients or devices that only support weak ciphers will stop connecting.

## 1.10
**HTTP admin redirected to HTTPS.** *L1 · auto-fix*

- **Why:** stops credentials being typed into a plain HTTP page.
- **Source:** `/system/global` (`admin-https-redirect`).
- **Pass:** `enable`.

## 1.11
**Admin HTTPS refuses TLS 1.0 and 1.1.** *L1 · auto-fix*

- **Why:** both versions are deprecated and have known weaknesses.
- **Source:** `/system/global` (`admin-https-ssl-versions`).
- **Pass:** the value is set and contains neither `tlsv1-0` nor `tlsv1-1`.
- **Fix:** `set admin-https-ssl-versions tlsv1-2 tlsv1-3`.
- **Caution:** an old browser or script that only speaks TLS 1.0/1.1 will lose access to the admin GUI.

## 1.12
**Maintainer account disabled.** *L1 · auto-fix*

- **Why:** the console `maintainer` account gives password-recovery access when someone has physical or serial access. It is a backdoor if the device is not physically secured.
- **Source:** `/system/global` (`admin-maintainer`).
- **Pass:** `disable`.
- **Caution:** disabling it removes a recovery route if every admin password is lost. Keep a tested recovery plan.

## 1.13
**Static-key TLS ciphers disabled.** *L1 · auto-fix*

- **Why:** static-key ciphers have no forward secrecy; a stolen key decrypts recorded traffic.
- **Source:** `/system/global` (`ssl-static-key-ciphers`).
- **Pass:** `disable`.

## 1.14
**Config revision saved on logout.** *L2 · auto-fix*

- **Why:** keeps a history so an unwanted change can be rolled back and attributed.
- **Source:** `/system/global` (`revision-backup-on-logout`).
- **Pass:** `enable`.

## 1.15
**Admin SCP disabled.** *L2 · auto-fix*

- **Why:** SCP lets an admin download the whole configuration, including secrets, over SSH.
- **Source:** `/system/global` (`admin-scp`).
- **Pass:** `disable`.
- **Caution:** anything that backs up the device via SCP will stop working.

## 2.1
**SNMP disabled or v3-only.** *L1 · manual*

- **Why:** SNMP v1/v2c use a shared community string sent in clear text.
- **Source:** `/system.snmp/sysinfo` (`status`) and `/system.snmp/community`.
- **Pass:** SNMP disabled, **or** enabled with zero v1/v2c communities.
- **Limit:** the check does not inspect the SNMPv3 users themselves.

## 2.2
**NTP synchronisation.** *L1 · auto-fix*

- **Why:** correct timestamps are essential for log correlation and incident investigation.
- **Source:** `/system/ntp` (`ntpsync`).
- **Pass:** `enable`.
- **Note:** the check does not verify that the configured servers are reachable.

## 3.1
**Remote logging.** *L1 · manual*

- **Why:** logs stored only on the device can be erased by an intruder or lost with the device.
- **Source:** `/log.syslogd/setting` (`status`, `server`).
- **Pass:** enabled **and** a server set.
- **Fix:** `config log syslogd setting` → `set status enable`, `set server <ip>`.
- **Limit:** only the first syslog target is checked, not FortiAnalyzer settings.
- **Why no auto-fix:** it needs a server address that only you know.

## 3.2
**Policy traffic logging.** *L1 · manual*

- **Why:** without traffic logs you cannot see what the firewall allowed.
- **Source:** `/firewall/policy`. SSH: `show firewall policy`.
- **Pass:** every policy whose action is `accept` has `logtraffic` set to `all` or `utm`.
- **Fix:** per policy, `set logtraffic all`.
- **Why no auto-fix:** per-policy edits, and full logging can increase log volume noticeably.
