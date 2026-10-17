#!/usr/bin/env python3
"""
main.py
-------
CLI entry point for the FortiGate CIS Benchmark compliance checker.

Usage examples
--------------
REST API backend:
    python -m fortigate_cis_checker.main \\
        --backend api --host 192.0.2.1 --token "$FGT_API_TOKEN" \\
        --csv out/report.csv --html out/report.html

SSH backend:
    python -m fortigate_cis_checker.main \\
        --backend ssh --host 192.0.2.1 --username readonly_cis \\
        --key-file ~/.ssh/id_fortigate_readonly \\
        --csv out/report.csv --html out/report.html

Credentials can also be supplied via environment variables so they never
appear in shell history:
    FGT_API_TOKEN, FGT_SSH_PASSWORD
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
from pathlib import Path

try:
    from .connector import (
        FortiGateAPIClient,
        FortiGateConnectionError,
        FortiGateSSHClient,
    )
    from .reporting import print_console_report, write_csv_report, write_html_report
    from .rules import ALL_RULES, RuleContext, RuleResult, Status
except ImportError:
    from connector import (
        FortiGateAPIClient,
        FortiGateConnectionError,
        FortiGateSSHClient,
    )
    from reporting import print_console_report, write_csv_report, write_html_report
    from rules import ALL_RULES, RuleContext, RuleResult, Status

logger = logging.getLogger("fortigate_cis")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only CIS Benchmark compliance checker for FortiGate."
    )
    p.add_argument("--backend", choices=["api", "ssh"], required=True)
    p.add_argument("--host", required=True, help="FortiGate management IP or hostname")
    p.add_argument("--port", type=int, default=None, help="Override default port (443 for api, 22 for ssh)")
    p.add_argument("--vdom", default="root", help="VDOM to query (API backend only)")

    # API auth
    p.add_argument("--token", default=None, help="REST API token (or set FGT_API_TOKEN env var)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (lab/test only)")

    # SSH auth
    p.add_argument("--username", default=None, help="SSH username (read-only admin profile)")
    p.add_argument("--password", default=None, help="SSH password (or set FGT_SSH_PASSWORD env var, or omit for prompt)")
    p.add_argument("--key-file", default=None, help="Path to SSH private key")

    # Output
    p.add_argument("--csv", default=None, help="Path to write CSV report")
    p.add_argument("--html", default=None, help="Path to write HTML report")
    p.add_argument("--level", type=int, choices=[1, 2], default=None, help="Only run checks at this CIS level")
    p.add_argument("--fail-on-warn", action="store_true", help="Exit non-zero if any WARN result is present")
    p.add_argument("-v", "--verbose", action="store_true")

    return p


def make_context_api(args: argparse.Namespace) -> RuleContext:
    token = args.token or os.environ.get("FGT_API_TOKEN")
    if not token:
        sys.exit("ERROR: no API token provided (--token or FGT_API_TOKEN env var)")

    client = FortiGateAPIClient(
        host=args.host,
        token=token,
        port=args.port or 443,
        verify_ssl=not args.insecure,
        vdom=args.vdom,
    )
    # Fail fast with a clear message if creds/host are wrong.
    client.get_system_status()

    return RuleContext(backend="api", cmdb_fetch=client.cmdb, monitor_fetch=client.monitor)


def make_context_ssh(args: argparse.Namespace) -> RuleContext:
    if not args.username:
        sys.exit("ERROR: --username is required for the SSH backend")

    password = args.password or os.environ.get("FGT_SSH_PASSWORD")
    if not args.key_file and not password:
        password = getpass.getpass(f"SSH password for {args.username}@{args.host}: ")

    client = FortiGateSSHClient(
        host=args.host,
        username=args.username,
        password=password,
        key_filename=args.key_file,
        port=args.port or 22,
    )
    client.connect()

    return RuleContext(backend="ssh", cli_fetch=client.run_cli)


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    try:
        if args.backend == "api":
            ctx = make_context_api(args)
        else:
            ctx = make_context_ssh(args)
    except FortiGateConnectionError as exc:
        logger.error(str(exc))
        return 2
    except RuntimeError as exc:
        logger.error(str(exc))
        return 2

    rules = ALL_RULES
    if args.level is not None:
        rules = [r for r in rules if True]  # level filter applied after running, see below

    results: list[RuleResult] = []
    for rule_fn in rules:
        try:
            result = rule_fn(ctx)
        except Exception as exc:  # a single bad rule should not kill the whole run
            logger.exception("Rule %s raised an unexpected exception", getattr(rule_fn, "__name__", rule_fn))
            result = RuleResult(
                rule_id="?",
                title=getattr(rule_fn, "__name__", str(rule_fn)),
                status=Status.ERROR,
                level=0,
                expected="n/a",
                actual=f"unhandled exception: {exc}",
                remediation="n/a",
            )
        results.append(result)

    if args.level is not None:
        results = [r for r in results if r.level == args.level]

    print_console_report(results, target=args.host)

    if args.csv:
        Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
        write_csv_report(results, args.csv)
        logger.info("CSV report written to %s", args.csv)

    if args.html:
        Path(args.html).parent.mkdir(parents=True, exist_ok=True)
        write_html_report(results, args.html, target=args.host)
        logger.info("HTML report written to %s", args.html)

    fail_count = sum(1 for r in results if r.status == Status.FAIL)
    warn_count = sum(1 for r in results if r.status == Status.WARN)
    if fail_count > 0:
        return 1
    if args.fail_on_warn and warn_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
