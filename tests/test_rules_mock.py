"""
test_rules_mock.py
-------------------
Runs every rule against a fabricated (mock) FortiGate config so you can:
  - demo the tool without real hardware/VM access
  - sanity-check that each rule's parsing logic works
  - use this as the basis for a "before/after hardening" demo in your report

Run directly:
    python -m fortigate_cis_checker.tests.test_rules_mock
or with pytest:
    pytest fortigate_cis_checker/tests/test_rules_mock.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fortigate_cis_checker.reporting import print_console_report, write_html_report
from fortigate_cis_checker.rules import ALL_RULES, RuleContext, Status

# --------------------------------------------------------------------------- #
# Two fabricated CMDB snapshots: one intentionally hardened, one intentionally
# weak, so you can show contrast in your project write-up.
# --------------------------------------------------------------------------- #

HARDENED_CMDB = {
    "/system/password-policy": {"results": [{
        "status": "enable", "minimum-length": 16,
        "min-lower-case-letter": 1, "min-upper-case-letter": 1,
        "min-number": 1, "min-non-alphanumeric": 1,
    }]},
    "/system/global": {"results": [{
        "admin-lockout-threshold": 3, "admin-lockout-duration": 120,
        "admintimeout": 5, "pre-login-banner": "enable",
    }]},
    "/system/interface": {"results": [
        {"name": "port1", "allowaccess": "https ssh"},
        {"name": "port2", "allowaccess": "ping"},
    ]},
    "/system.snmp/sysinfo": {"results": [{"status": "disable"}]},
    "/system.snmp/community": {"results": []},
    "/system/ntp": {"results": [{"ntpsync": "enable"}]},
    "/log.syslogd/setting": {"results": [{"status": "enable", "server": "10.0.0.50"}]},
    "/system/auto-install": {"results": [{"auto-install-config": "disable", "auto-install-image": "disable"}]},
    "/system/admin": {"results": [
        {"name": "admin", "trusthost1": "10.0.0.0 255.255.255.0"},
        {"name": "cis_checker_api", "trusthost1": "10.0.0.5 255.255.255.255"},
    ]},
}

WEAK_CMDB = {
    "/system/password-policy": {"results": [{
        "status": "disable", "minimum-length": 8,
        "min-lower-case-letter": 0, "min-upper-case-letter": 0,
        "min-number": 0, "min-non-alphanumeric": 0,
    }]},
    "/system/global": {"results": [{
        "admin-lockout-threshold": 0, "admin-lockout-duration": 0,
        "admintimeout": 60, "pre-login-banner": "disable",
    }]},
    "/system/interface": {"results": [
        {"name": "port1", "allowaccess": "https http ssh telnet"},
        {"name": "wan1", "allowaccess": "https http ping"},
    ]},
    "/system.snmp/sysinfo": {"results": [{"status": "enable"}]},
    "/system.snmp/community": {"results": [{"name": "public"}, {"name": "private"}]},
    "/system/ntp": {"results": [{"ntpsync": "disable"}]},
    "/log.syslogd/setting": {"results": [{"status": "disable", "server": ""}]},
    "/system/auto-install": {"results": [{"auto-install-config": "enable", "auto-install-image": "enable"}]},
    "/system/admin": {"results": [
        {"name": "admin", "trusthost1": "0.0.0.0 0.0.0.0"},
    ]},
}


def make_mock_cmdb_fetch(snapshot: dict):
    def _fetch(path: str) -> dict:
        return snapshot.get(path, {"results": []})
    return _fetch


def run_against(snapshot: dict, label: str):
    ctx = RuleContext(backend="api", cmdb_fetch=make_mock_cmdb_fetch(snapshot))
    results = [rule(ctx) for rule in ALL_RULES]
    print_console_report(results, target=f"MOCK ({label})")
    return results


def test_hardened_config_mostly_passes():
    results = run_against(HARDENED_CMDB, "hardened")
    fails = [r for r in results if r.status == Status.FAIL]
    assert not fails, f"Expected hardened config to pass, but failed: {[r.rule_id for r in fails]}"


def test_weak_config_mostly_fails():
    results = run_against(WEAK_CMDB, "weak")
    passes = [r for r in results if r.status == Status.PASS]
    assert len(passes) <= 1, f"Expected weak config to fail nearly everything, but passed: {[r.rule_id for r in passes]}"


if __name__ == "__main__":
    hardened_results = run_against(HARDENED_CMDB, "hardened / after remediation")
    weak_results = run_against(WEAK_CMDB, "weak / default-ish")

    out_dir = Path(__file__).resolve().parents[1] / "reports"
    out_dir.mkdir(exist_ok=True)
    write_html_report(hardened_results, str(out_dir / "demo_hardened.html"), target="MOCK-hardened")
    write_html_report(weak_results, str(out_dir / "demo_weak.html"), target="MOCK-weak")
    print(f"\nDemo HTML reports written to {out_dir}/")
