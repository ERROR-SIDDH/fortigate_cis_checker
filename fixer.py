"""
fixer.py
--------
Optional write path: apply (and undo) the settings behind a failed check.

Kept separate from connector.py on purpose: the scanner stays read-only,
and this module needs its own token (FGT_WRITE_TOKEN) bound to a
read-write profile. Before the first apply of a rule the previous values
are saved to undo_state.json so `undo` can restore them exactly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple

import requests
import urllib3

STATE_FILE = Path(__file__).resolve().parent / "undo_state.json"

# rule id -> (CMDB path, {setting: value}). Only single-table settings are
# here; rules that need per-object edits (interfaces, policies) are not.
FIXES: Dict[str, Tuple[str, dict]] = {
    "1.1": ("/system/password-policy", {"status": "enable", "minimum-length": 14}),
    "1.2": ("/system/global", {"admin-lockout-threshold": 3, "admin-lockout-duration": 60}),
    "1.3": ("/system/global", {"admintimeout": 5}),
    "1.5": ("/system/global", {"pre-login-banner": "enable"}),
    "1.6": ("/system/auto-install", {"auto-install-config": "disable", "auto-install-image": "disable"}),
    "1.9": ("/system/global", {"strong-crypto": "enable"}),
    "1.10": ("/system/global", {"admin-https-redirect": "enable"}),
    "1.11": ("/system/global", {"admin-https-ssl-versions": "tlsv1-2 tlsv1-3"}),
    "1.12": ("/system/global", {"admin-maintainer": "disable"}),
    "1.13": ("/system/global", {"ssl-static-key-ciphers": "disable"}),
    "1.14": ("/system/global", {"revision-backup-on-logout": "enable"}),
    "1.15": ("/system/global", {"admin-scp": "disable"}),
    "2.2": ("/system/ntp", {"ntpsync": "enable"}),
}


def _load() -> dict:
    return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}


def can_undo(rule_id: str) -> bool:
    return rule_id in _load()


class FortiGateWriter:
    def __init__(self, host: str, token: str, port: int = 443, verify_ssl: bool = True, vdom: str = "root"):
        self.base = f"https://{host}:{port}/api/v2/cmdb"
        self.verify, self.vdom = verify_ssl, vdom
        self.s = requests.Session()
        self.s.headers["Authorization"] = f"Bearer {token}"
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _current(self, path: str) -> dict:
        r = self.s.get(self.base + path, params={"vdom": self.vdom}, verify=self.verify, timeout=15)
        r.raise_for_status()
        res = r.json().get("results", {})
        return res[0] if isinstance(res, list) else res

    def _put(self, path: str, values: dict) -> None:
        r = self.s.put(self.base + path, params={"vdom": self.vdom}, json=values, verify=self.verify, timeout=15)
        if r.status_code != 200:
            raise RuntimeError(f"PUT {path} -> {r.status_code}: {r.text[:200]}")

    def apply(self, rule_id: str) -> str:
        if rule_id not in FIXES:
            raise KeyError(f"no automatic fix for {rule_id}")
        path, values = FIXES[rule_id]
        state = _load()
        if rule_id not in state:  # never overwrite the original with an already-fixed value
            cur = self._current(path)
            state[rule_id] = {"path": path, "previous": {k: cur[k] for k in values if k in cur}}
            STATE_FILE.write_text(json.dumps(state, indent=2))
        self._put(path, values)
        return f"applied {values}"

    def undo(self, rule_id: str) -> str:
        state = _load()
        if rule_id not in state:
            raise KeyError(f"nothing saved to undo for {rule_id}")
        entry = state[rule_id]
        self._put(entry["path"], entry["previous"])
        del state[rule_id]
        STATE_FILE.write_text(json.dumps(state, indent=2))
        return f"restored {entry['previous']}"
