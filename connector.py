"""
connector.py
------------
Read-only connection handlers for FortiGate.

Two backends are supported:
  1. REST API  (recommended) - uses an API token bound to a read-only
     admin profile (see docs/setup_readonly_user.md for how to create one).
  2. SSH CLI   - uses an admin account whose profile is set to
     "read-only" access on the relevant ADOM/VDOM, and issues only
     'get' / 'show' / 'diagnose' style commands - nothing that writes.

Both backends expose the same interface: get_system_status(),
get_config(path), run_cli(command) -> so the rule engine does not need
to know which transport is in use.
"""

from __future__ import annotations

import json
import logging
import ssl
from dataclasses import dataclass
from typing import Any, Optional

import requests
import urllib3

logger = logging.getLogger("fortigate_cis.connector")


class FortiGateConnectionError(Exception):
    """Raised when the FortiGate cannot be reached or auth fails."""


# --------------------------------------------------------------------------- #
# REST API backend
# --------------------------------------------------------------------------- #

class FortiGateAPIClient:
    """
    Thin wrapper around the FortiGate REST API (v2) using a read-only
    API token. Only performs HTTP GET requests - the read-only admin
    profile on the FortiGate side additionally enforces this server-side,
    so this class is a second layer, not the only layer, of protection.
    """

    def __init__(
        self,
        host: str,
        token: str,
        port: int = 443,
        verify_ssl: bool = True,
        timeout: int = 15,
        vdom: str = "root",
    ):
        self.base_url = f"https://{host}:{port}/api/v2"
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.vdom = vdom
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning(
                "SSL verification is DISABLED. Only use this for lab/test "
                "environments - never in production."
            )

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        url = f"{self.base_url}{path}"
        params = dict(params or {})
        params.setdefault("vdom", self.vdom)
        try:
            resp = self.session.get(
                url, params=params, verify=self.verify_ssl, timeout=self.timeout
            )
        except requests.exceptions.SSLError as exc:
            raise FortiGateConnectionError(
                f"TLS/SSL error contacting {url}: {exc}"
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise FortiGateConnectionError(
                f"Could not connect to {url}: {exc}"
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise FortiGateConnectionError(f"Timed out contacting {url}: {exc}") from exc

        if resp.status_code == 401:
            raise FortiGateConnectionError(
                "Authentication failed (401). Check the API token and that "
                "the admin profile permits read access to this endpoint."
            )
        if resp.status_code == 403:
            raise FortiGateConnectionError(
                f"Forbidden (403) for {path}. The read-only profile may not "
                "have access to this CMDB table."
            )
        if resp.status_code == 404:
            # Feature/table not present on this box (e.g. licensing, model).
            logger.debug("404 for %s - treating as 'not configured'.", path)
            return {"http_status": 404, "results": []}
        if resp.status_code >= 500:
            raise FortiGateConnectionError(
                f"FortiGate returned server error {resp.status_code} for {path}"
            )

        try:
            data = resp.json()
        except ValueError as exc:
            raise FortiGateConnectionError(
                f"Non-JSON response from {url} (status {resp.status_code})"
            ) from exc

        data["http_status"] = resp.status_code
        return data

    # -- convenience wrappers for the CMDB / monitor endpoints used below -- #

    def cmdb(self, path: str, params: Optional[dict] = None) -> dict:
        """GET a CMDB config table, e.g. cmdb('/cmdb/system/global')."""
        return self._get(f"/cmdb{path}", params=params)

    def monitor(self, path: str, params: Optional[dict] = None) -> dict:
        """GET a runtime/monitor endpoint, e.g. monitor('/system/status')."""
        return self._get(f"/monitor{path}", params=params)

    def get_system_status(self) -> dict:
        return self.monitor("/system/status")


# --------------------------------------------------------------------------- #
# SSH backend
# --------------------------------------------------------------------------- #

# Only these command prefixes are permitted to be sent over SSH. This is a
# client-side allow-list in addition to the FortiGate read-only admin
# profile enforcing the same restriction server-side.
_ALLOWED_CLI_PREFIXES = ("get ", "show ", "diagnose sys ", "diagnose debug")


@dataclass
class SSHResult:
    command: str
    output: str


class FortiGateSSHClient:
    """
    SSH CLI backend. Requires `paramiko`. The admin account used here
    must be configured on the FortiGate with:
        config system accprofile
            edit "readonly_cis"
                set ... read
            next
        end
    and the admin user's 'accprofile' set to that profile - so even if
    this client were misused, the device itself refuses any write.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: int = 22,
        timeout: int = 15,
    ):
        try:
            import paramiko  # noqa: F401  (import here so REST-only users don't need it)
        except ImportError as exc:
            raise RuntimeError(
                "paramiko is required for the SSH backend: pip install paramiko"
            ) from exc

        self._paramiko = __import__("paramiko")
        self.host = host
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.port = port
        self.timeout = timeout
        self._client: Optional[Any] = None

    def connect(self) -> None:
        paramiko = self._paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                key_filename=self.key_filename,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=bool(self.key_filename),
            )
        except Exception as exc:  # paramiko raises several distinct types
            raise FortiGateConnectionError(f"SSH connection failed: {exc}") from exc
        self._client = client

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> "FortiGateSSHClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def run_cli(self, command: str) -> str:
        if not command.strip().startswith(_ALLOWED_CLI_PREFIXES):
            raise PermissionError(
                f"Refusing to send non-read-only command over SSH: {command!r}"
            )
        if self._client is None:
            raise FortiGateConnectionError("Not connected - call connect() first.")

        stdin, stdout, stderr = self._client.exec_command(command, timeout=self.timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        if err.strip():
            logger.debug("stderr for %r: %s", command, err.strip())
        return out
