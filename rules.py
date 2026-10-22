"""
rules.py
--------
CIS FortiGate 7.x Benchmark-mapped checks.

Each Rule maps to a named, publicly documented FortiGate hardening
control that the CIS Benchmark for FortiGate 7.x is built around
(password policy, admin lockout, session timeout, secure management
access, logging, NTP, SNMP, etc.). Rule text below is written
independently and paraphrased in our own words for teaching purposes;
it is NOT a copy of CIS's copyrighted PDF. For submission/citation
purposes, students should reference the official CIS FortiGate 7.0.x
Benchmark document (CIS SecureSuite membership required) alongside
this tool, and adjust rule IDs to match the exact section numbers in
whichever benchmark revision they were issued.

Each rule receives a `ctx` (RuleContext) that abstracts over whichever
backend (REST/SSH) fetched the data, and returns a RuleResult.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"          # setting present but suboptimal / needs review
    ERROR = "ERROR"        # could not evaluate (network/API issue, missing data)
    NOT_APPLICABLE = "N/A"


@dataclass
class RuleResult:
    rule_id: str
    title: str
    status: Status
    level: int                    # CIS Implementation Level 1 or 2
    expected: str
    actual: str
    remediation: str
    details: str = ""


@dataclass
class RuleContext:
    """
    Bundles whatever data source is active. Backend-specific fetch
    functions are injected so rules stay backend-agnostic.
    """
    backend: str                                   # "api" or "ssh"
    cmdb_fetch: Optional[Callable[[str], dict]] = None      # api.cmdb(path)
    monitor_fetch: Optional[Callable[[str], dict]] = None   # api.monitor(path)
    cli_fetch: Optional[Callable[[str], str]] = None        # ssh.run_cli(cmd)
    cache: dict = field(default_factory=dict)

    def cmdb(self, path: str) -> dict:
        if self.cmdb_fetch is None:
            raise RuntimeError("cmdb_fetch not available on this backend")
        if path not in self.cache:
            self.cache[path] = self.cmdb_fetch(path)
        return self.cache[path]

    def cli(self, command: str) -> str:
        if self.cli_fetch is None:
            raise RuntimeError("cli_fetch not available on this backend")
        key = f"cli::{command}"
        if key not in self.cache:
            self.cache[key] = self.cli_fetch(command)
        return self.cache[key]


Rule = Callable[[RuleContext], RuleResult]


# --------------------------------------------------------------------------- #
# Helpers for parsing SSH `get`/`show` style CLI text output
# --------------------------------------------------------------------------- #

def _cli_kv(text: str, key: str) -> Optional[str]:
    """Extract 'key : value' or 'key    value' style output from CLI text."""
    pattern = rf"^\s*{re.escape(key)}\s*[:\s]\s*(.+?)\s*$"
    m = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else None


def _first_result(data: dict) -> dict:
    results = data.get("results")
    if isinstance(results, list):
        return results[0] if results else {}
    if isinstance(results, dict):
        return results
    return {}


# --------------------------------------------------------------------------- #
# Individual rule implementations
# --------------------------------------------------------------------------- #

def rule_password_min_length(ctx: RuleContext) -> RuleResult:
    rid, title, level = "1.1", "Admin password minimum length enforced", 1
    remediation = (
        "config system password-policy\n"
        "  set status enable\n"
        "  set minimum-length 14\n"
        "end"
    )
    try:
        if ctx.backend == "api":
            data = _first_result(ctx.cmdb("/system/password-policy"))
            status_enabled = str(data.get("status", "")).lower() == "enable"
            min_len = int(data.get("minimum-length", 0) or 0)
        else:
            text = ctx.cli("get system password-policy")
            status_enabled = (_cli_kv(text, "status") or "").lower() == "enable"
            min_len = int(_cli_kv(text, "minimum-length") or 0)

        actual = f"status={'enable' if status_enabled else 'disable'}, minimum-length={min_len}"
        if status_enabled and min_len >= 14:
            return RuleResult(rid, title, Status.PASS, level, "enabled, >=14 chars", actual, remediation)
        return RuleResult(rid, title, Status.FAIL, level, "enabled, >=14 chars", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "enabled, >=14 chars", str(exc), remediation)


def rule_admin_lockout(ctx: RuleContext) -> RuleResult:
    rid, title, level = "1.2", "Admin lockout threshold and duration configured", 1
    remediation = (
        "config system global\n"
        "  set admin-lockout-threshold 3\n"
        "  set admin-lockout-duration 60\n"
        "end"
    )
    try:
        if ctx.backend == "api":
            data = _first_result(ctx.cmdb("/system/global"))
            threshold = int(data.get("admin-lockout-threshold", 0) or 0)
            duration = int(data.get("admin-lockout-duration", 0) or 0)
        else:
            text = ctx.cli("get system global")
            threshold = int(_cli_kv(text, "admin-lockout-threshold") or 0)
            duration = int(_cli_kv(text, "admin-lockout-duration") or 0)

        actual = f"threshold={threshold}, duration={duration}s"
        if 1 <= threshold <= 3 and duration >= 60:
            return RuleResult(rid, title, Status.PASS, level, "threshold<=3, duration>=60s", actual, remediation)
        return RuleResult(rid, title, Status.FAIL, level, "threshold<=3, duration>=60s", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "threshold<=3, duration>=60s", str(exc), remediation)


def rule_admin_idle_timeout(ctx: RuleContext) -> RuleResult:
    rid, title, level = "1.3", "Administrative idle timeout set to <=5 minutes", 1
    remediation = "config system global\n  set admintimeout 5\nend"
    try:
        if ctx.backend == "api":
            data = _first_result(ctx.cmdb("/system/global"))
            timeout = int(data.get("admintimeout", 0) or 0)
        else:
            text = ctx.cli("get system global")
            timeout = int(_cli_kv(text, "admintimeout") or 0)

        actual = f"admintimeout={timeout} minutes"
        if 1 <= timeout <= 5:
            return RuleResult(rid, title, Status.PASS, level, "<=5 minutes", actual, remediation)
        return RuleResult(rid, title, Status.FAIL, level, "<=5 minutes", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "<=5 minutes", str(exc), remediation)


def rule_https_admin_access_only(ctx: RuleContext) -> RuleResult:
    rid, title, level = "1.4", "Only HTTPS/SSH (not HTTP/Telnet) permitted for admin access on interfaces", 1
    remediation = (
        "config system interface\n"
        "  edit <interface>\n"
        "    unset allowaccess   ! then re-add only https, ssh (and ping if needed)\n"
        "    set allowaccess https ssh\n"
        "  next\n"
        "end"
    )
    try:
        if ctx.backend == "api":
            data = ctx.cmdb("/system/interface")
            interfaces = data.get("results", []) or []
            offenders = []
            for iface in interfaces:
                access = iface.get("allowaccess", "") or ""
                access_list = access.split() if isinstance(access, str) else access
                if "http" in access_list or "telnet" in access_list:
                    offenders.append(iface.get("name", "?"))
        else:
            text = ctx.cli("show system interface")
            offenders = []
            for block in re.split(r"(?=edit \")", text):
                name_m = re.search(r'edit "([^"]+)"', block)
                access_m = re.search(r"set allowaccess (.+)", block)
                if name_m and access_m:
                    access_list = access_m.group(1).split()
                    if "http" in access_list or "telnet" in access_list:
                        offenders.append(name_m.group(1))

        actual = f"interfaces with http/telnet allowed: {offenders or 'none'}"
        if not offenders:
            return RuleResult(rid, title, Status.PASS, level, "no interface allows http/telnet", actual, remediation)
        return RuleResult(rid, title, Status.FAIL, level, "no interface allows http/telnet", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "no interface allows http/telnet", str(exc), remediation)


def rule_snmp_v3_only(ctx: RuleContext) -> RuleResult:
    rid, title, level = "2.1", "SNMP restricted to v3 (no v1/v2c communities), or disabled", 1
    remediation = (
        "config system snmp sysinfo\n"
        "  set status disable   ! if SNMP unused, else configure snmpv3 only\n"
        "end\n"
        "config system snmp community\n"
        "  ! remove all v1/v2c communities\n"
        "end"
    )
    try:
        if ctx.backend == "api":
            sysinfo = _first_result(ctx.cmdb("/system.snmp/sysinfo"))
            snmp_enabled = str(sysinfo.get("status", "")).lower() == "enable"
            communities = ctx.cmdb("/system.snmp/community").get("results", []) or []
        else:
            text = ctx.cli("get system snmp sysinfo")
            snmp_enabled = (_cli_kv(text, "status") or "").lower() == "enable"
            comm_text = ctx.cli("show system snmp community")
            communities = re.findall(r'edit "([^"]+)"', comm_text)

        actual = f"snmp_enabled={snmp_enabled}, v1/v2c_communities={len(communities)}"
        if not snmp_enabled:
            return RuleResult(rid, title, Status.PASS, level, "disabled or v3-only", actual, remediation)
        if snmp_enabled and len(communities) == 0:
            return RuleResult(rid, title, Status.PASS, level, "disabled or v3-only", actual, remediation)
        return RuleResult(rid, title, Status.FAIL, level, "disabled or v3-only", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "disabled or v3-only", str(exc), remediation)


def rule_ntp_configured(ctx: RuleContext) -> RuleResult:
    rid, title, level = "2.2", "NTP synchronization enabled (accurate log timestamps)", 1
    remediation = "config system ntp\n  set ntpsync enable\n  set type custom\n  ! set trusted NTP servers\nend"
    try:
        if ctx.backend == "api":
            data = _first_result(ctx.cmdb("/system/ntp"))
            enabled = str(data.get("ntpsync", "")).lower() == "enable"
        else:
            text = ctx.cli("get system ntp")
            enabled = (_cli_kv(text, "ntpsync") or "").lower() == "enable"

        actual = f"ntpsync={'enable' if enabled else 'disable'}"
        if enabled:
            return RuleResult(rid, title, Status.PASS, level, "ntpsync enabled", actual, remediation)
        return RuleResult(rid, title, Status.FAIL, level, "ntpsync enabled", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "ntpsync enabled", str(exc), remediation)


def rule_login_banner_configured(ctx: RuleContext) -> RuleResult:
    rid, title, level = "1.5", "Pre-login administrative disclaimer/banner configured", 2
    remediation = (
        "config system global\n"
        "  set pre-login-banner enable\n"
        "end\n"
        "config system replacemsg admin pre_admin-disclaimer-text\n"
        "  set buffer \"Authorized users only. All activity may be monitored and reported.\"\n"
        "end"
    )
    try:
        if ctx.backend == "api":
            data = _first_result(ctx.cmdb("/system/global"))
            enabled = str(data.get("pre-login-banner", "")).lower() == "enable"
        else:
            text = ctx.cli("get system global")
            enabled = (_cli_kv(text, "pre-login-banner") or "").lower() == "enable"

        actual = f"pre-login-banner={'enable' if enabled else 'disable'}"
        if enabled:
            return RuleResult(rid, title, Status.PASS, level, "enabled", actual, remediation)
        return RuleResult(rid, title, Status.FAIL, level, "enabled", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "enabled", str(exc), remediation)


def rule_logging_enabled(ctx: RuleContext) -> RuleResult:
    rid, title, level = "3.1", "Event logging enabled to a remote target (FortiAnalyzer/syslog)", 1
    remediation = (
        "config log syslogd setting\n"
        "  set status enable\n"
        "  set server <syslog-server-ip>\n"
        "end"
    )
    try:
        if ctx.backend == "api":
            data = _first_result(ctx.cmdb("/log.syslogd/setting"))
            enabled = str(data.get("status", "")).lower() == "enable"
            server = data.get("server", "")
        else:
            text = ctx.cli("get log syslogd setting")
            enabled = (_cli_kv(text, "status") or "").lower() == "enable"
            server = _cli_kv(text, "server") or ""

        actual = f"status={'enable' if enabled else 'disable'}, server={server or 'unset'}"
        if enabled and server:
            return RuleResult(rid, title, Status.PASS, level, "remote logging enabled with server set", actual, remediation)
        return RuleResult(rid, title, Status.FAIL, level, "remote logging enabled with server set", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "remote logging enabled with server set", str(exc), remediation)


def rule_usb_firmware_install_disabled(ctx: RuleContext) -> RuleResult:
    rid, title, level = "1.6", "Auto-install of configuration/firmware from USB is disabled", 2
    remediation = "config system auto-install\n  set auto-install-config disable\n  set auto-install-image disable\nend"
    try:
        if ctx.backend == "api":
            data = _first_result(ctx.cmdb("/system/auto-install"))
            cfg = str(data.get("auto-install-config", "")).lower()
            img = str(data.get("auto-install-image", "")).lower()
        else:
            text = ctx.cli("get system auto-install")
            cfg = (_cli_kv(text, "auto-install-config") or "").lower()
            img = (_cli_kv(text, "auto-install-image") or "").lower()

        actual = f"auto-install-config={cfg or 'unknown'}, auto-install-image={img or 'unknown'}"
        if cfg == "disable" and img == "disable":
            return RuleResult(rid, title, Status.PASS, level, "both disabled", actual, remediation)
        return RuleResult(rid, title, Status.FAIL, level, "both disabled", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "both disabled", str(exc), remediation)


def rule_password_policy_complexity(ctx: RuleContext) -> RuleResult:
    rid, title, level = "1.7", "Admin password policy enforces character-type complexity", 2
    remediation = (
        "config system password-policy\n"
        "  set status enable\n"
        "  set min-lower-case-letter 1\n"
        "  set min-upper-case-letter 1\n"
        "  set min-number 1\n"
        "  set min-non-alphanumeric 1\n"
        "end"
    )
    try:
        if ctx.backend == "api":
            data = _first_result(ctx.cmdb("/system/password-policy"))
            checks = {
                "min-lower-case-letter": int(data.get("min-lower-case-letter", 0) or 0),
                "min-upper-case-letter": int(data.get("min-upper-case-letter", 0) or 0),
                "min-number": int(data.get("min-number", 0) or 0),
                "min-non-alphanumeric": int(data.get("min-non-alphanumeric", 0) or 0),
            }
        else:
            text = ctx.cli("get system password-policy")
            checks = {
                k: int(_cli_kv(text, k) or 0)
                for k in (
                    "min-lower-case-letter",
                    "min-upper-case-letter",
                    "min-number",
                    "min-non-alphanumeric",
                )
            }

        actual = ", ".join(f"{k}={v}" for k, v in checks.items())
        if all(v >= 1 for v in checks.values()):
            return RuleResult(rid, title, Status.PASS, level, "all complexity minimums >=1", actual, remediation)
        return RuleResult(rid, title, Status.WARN, level, "all complexity minimums >=1", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "all complexity minimums >=1", str(exc), remediation)


def rule_default_admin_renamed_or_disabled(ctx: RuleContext) -> RuleResult:
    rid, title, level = "1.8", "Default 'admin' account renamed, disabled, or restricted by trusted hosts", 1
    remediation = (
        "config system admin\n"
        "  edit admin\n"
        "    set trusthost1 <mgmt-subnet>/<mask>\n"
        "  next\n"
        "end\n"
        "! or rename via GUI/API (rename not supported directly in CLI - "
        "create a new named admin with same rights and disable/delete 'admin')"
    )
    try:
        if ctx.backend == "api":
            admins = ctx.cmdb("/system/admin").get("results", []) or []
            default_admin = next((a for a in admins if a.get("name") == "admin"), None)
            if default_admin is None:
                actual = "no account named 'admin' exists"
                return RuleResult(rid, title, Status.PASS, level, "'admin' absent or trusthost-restricted", actual, remediation)
            trusthost1 = default_admin.get("trusthost1", "0.0.0.0 0.0.0.0")
        else:
            text = ctx.cli("show system admin")
            if 'edit "admin"' not in text:
                return RuleResult(
                    rid, title, Status.PASS, level, "'admin' absent or trusthost-restricted",
                    "no account named 'admin' exists", remediation,
                )
            block_m = re.search(r'edit "admin"(.*?)next', text, re.DOTALL)
            block = block_m.group(1) if block_m else ""
            trusthost1 = _cli_kv(block, "trusthost1") or "0.0.0.0 0.0.0.0"

        actual = f"admin trusthost1={trusthost1}"
        if trusthost1.strip() not in ("0.0.0.0 0.0.0.0", ""):
            return RuleResult(rid, title, Status.PASS, level, "'admin' absent or trusthost-restricted", actual, remediation)
        return RuleResult(rid, title, Status.FAIL, level, "'admin' absent or trusthost-restricted", actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, "'admin' absent or trusthost-restricted", str(exc), remediation)


def _global_check(ctx, rid, title, level, key, expected, ok, remediation) -> RuleResult:
    """Shared body for rules that test a single `config system global` value."""
    try:
        if ctx.backend == "api":
            val = str(_first_result(ctx.cmdb("/system/global")).get(key, "")).lower()
        else:
            val = (_cli_kv(ctx.cli("get system global"), key) or "").lower()
        actual = f"{key}={val or 'unset'}"
        return RuleResult(rid, title, Status.PASS if ok(val) else Status.FAIL, level, expected, actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, expected, str(exc), remediation)


def rule_strong_crypto(ctx: RuleContext) -> RuleResult:
    return _global_check(
        ctx, "1.9", "Strong cryptography enforced (strong-crypto)", 1, "strong-crypto",
        "enable", lambda v: v == "enable",
        "config system global\n  set strong-crypto enable\nend")


def rule_https_redirect(ctx: RuleContext) -> RuleResult:
    return _global_check(
        ctx, "1.10", "HTTP admin requests redirected to HTTPS", 1, "admin-https-redirect",
        "enable", lambda v: v == "enable",
        "config system global\n  set admin-https-redirect enable\nend")


def rule_admin_tls_versions(ctx: RuleContext) -> RuleResult:
    return _global_check(
        ctx, "1.11", "Admin HTTPS refuses TLS 1.0 / 1.1", 1, "admin-https-ssl-versions",
        "no tlsv1-0 / tlsv1-1", lambda v: bool(v) and "tlsv1-0" not in v.split() and "tlsv1-1" not in v.split(),
        "config system global\n  set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend")


def rule_policy_logging(ctx: RuleContext) -> RuleResult:
    rid, title, level = "3.2", "Every accept firewall policy logs traffic", 1
    expected = "logtraffic is all/utm on every accept policy"
    remediation = "config firewall policy\n  edit <id>\n    set logtraffic all\n  next\nend"
    try:
        if ctx.backend == "api":
            pols = [(str(p.get("policyid")), p.get("action", "accept"), p.get("logtraffic", ""))
                    for p in ctx.cmdb("/firewall/policy").get("results", [])]
        else:
            text = ctx.cli("show firewall policy")
            # `show` omits defaults: action defaults to deny, logtraffic to utm
            pols = [(m.group(1), _cli_kv(m.group(2), "set action") or "deny",
                     _cli_kv(m.group(2), "set logtraffic") or "utm")
                    for m in re.finditer(r"edit (\d+)(.*?)\n\s*next", text, re.DOTALL)]
        bad = [i for i, action, log in pols if action == "accept" and log.lower() not in ("all", "utm")]
        actual = f"policies not logging: {bad}" if bad else f"{len(pols)} policies checked"
        return RuleResult(rid, title, Status.FAIL if bad else Status.PASS, level, expected, actual, remediation)
    except Exception as exc:
        return RuleResult(rid, title, Status.ERROR, level, expected, str(exc), remediation)


ALL_RULES: List[Rule] = [
    rule_password_min_length,
    rule_password_policy_complexity,
    rule_admin_lockout,
    rule_admin_idle_timeout,
    rule_https_admin_access_only,
    rule_default_admin_renamed_or_disabled,
    rule_login_banner_configured,
    rule_usb_firmware_install_disabled,
    rule_snmp_v3_only,
    rule_ntp_configured,
    rule_logging_enabled,
    rule_strong_crypto,
    rule_https_redirect,
    rule_admin_tls_versions,
    rule_policy_logging,
]
