import argparse
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from engine.alert import Alert
from engine.evaluator import run_rules
from engine.ingest import ingest, merge_events
from engine.report import (
    SEVERITY_ORDER,
    build_report,
    write_json_report,
    write_txt_report,
)
from engine.rule import load_rules
from storage.db import connect
from storage.repository import load_alert_ids, load_events, save_run

DEFAULT_RULES = Path(__file__).resolve().parent / "rules" / "rules.yaml"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mini_siem.py",
        description="Correlate security events from several sources and print alerts.",
    )
    parser.add_argument(
        "--scan",
        nargs="+",
        default=[],
        metavar="FILE",
        help="Network Scanner JSON report(s)",
    )
    parser.add_argument(
        "--auth-log",
        nargs="+",
        default=[],
        metavar="FILE",
        help="authentication log file(s)",
    )
    parser.add_argument(
        "--rules",
        default=str(DEFAULT_RULES),
        metavar="FILE",
        help="detection rules file (YAML)",
    )
    parser.add_argument(
        "--report-dir",
        default=None,
        metavar="DIR",
        help="write a JSON and a TXT report to this folder",
    )
    parser.add_argument(
        "--db",
        default=None,
        metavar="FILE",
        help="SQLite database that keeps events and alerts between runs",
    )
    return parser


def format_alert(alert: Alert, is_new: bool = False) -> str:
    title = f"[{alert.severity.upper()}] {alert.rule_id} {alert.rule_name}"
    if alert.mitre_technique:
        title += f" ({alert.mitre_technique})"
    if is_new:
        title += " [NEW]"
    when = alert.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return "\n".join(
        [
            title,
            f"  Time: {when}",
            f"  {alert.description}",
            f"  Evidence: {len(alert.event_ids)} event(s)",
        ]
    )


def severity_breakdown(alerts: list[Alert]) -> str:
    counts = Counter(alert.severity for alert in alerts)
    parts = [f"{name}: {counts[name]}" for name in SEVERITY_ORDER if counts[name]]
    return ", ".join(parts)


def alerts_line(alerts: list[Alert], new_count) -> str:
    if not alerts:
        return "Alerts: 0"
    line = f"Alerts: {len(alerts)} ({severity_breakdown(alerts)})"
    if new_count is not None:
        line += f", {new_count} new"
    return line


def main(argv=None, now=utc_now) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.scan and not args.auth_log:
        parser.error("provide at least one input with --scan or --auth-log")

    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as error:
        print(f"error: cannot load rules: {error}", file=sys.stderr)
        return 2

    try:
        new_events, rejected = ingest(
            scan_report_paths=args.scan,
            auth_log_paths=args.auth_log,
        )
    except (OSError, UnicodeDecodeError) as error:
        print(f"error: cannot read input: {error}", file=sys.stderr)
        return 2

    for message in rejected:
        print(f"warning: rejected input: {message}", file=sys.stderr)

    connection = None
    try:
        history = []
        known_alert_ids = set()
        if args.db is not None:
            try:
                connection = connect(args.db)
                history = load_events(connection)
                known_alert_ids = load_alert_ids(connection)
            except (sqlite3.Error, OSError, ValueError) as error:
                print(f"error: cannot use database: {error}", file=sys.stderr)
                return 2

        events = merge_events(history, new_events)
        alerts = run_rules(rules, events)
        fresh_ids = {
            alert.alert_id for alert in alerts if alert.alert_id not in known_alert_ids
        }
        use_db = connection is not None
        enabled = sum(1 for rule in rules if rule.enabled)

        print("Mini-SIEM")
        print(f"Events ingested: {len(new_events)}")
        print(f"Rejected inputs: {len(rejected)}")
        print(f"Rules loaded: {len(rules)} ({enabled} enabled)")
        if use_db:
            print(f"History: {len(history)} event(s) loaded from {args.db}")
            print(f"Events analyzed: {len(events)}")
        print(alerts_line(alerts, len(fresh_ids) if use_db else None))
        for alert in alerts:
            print()
            print(format_alert(alert, is_new=use_db and alert.alert_id in fresh_ids))

        if use_db:
            try:
                saved = save_run(connection, new_events, alerts)
            except sqlite3.Error as error:
                print(f"error: cannot save to database: {error}", file=sys.stderr)
                return 2
            print()
            print(
                f"Saved to {args.db}: {saved.events_new} new event(s), "
                f"{saved.alerts_new} new alert(s) "
                f"({saved.events_existing} event(s) and "
                f"{saved.alerts_existing} alert(s) already stored)"
            )

        if args.report_dir is not None:
            generated_at = now()
            report = build_report(events, alerts, rejected, rules, generated_at)
            try:
                json_path = write_json_report(report, args.report_dir, generated_at)
                txt_path = write_txt_report(report, args.report_dir, generated_at)
            except OSError as error:
                print(f"error: cannot write report: {error}", file=sys.stderr)
                return 2
            print()
            print(f"Report written: {json_path}")
            print(f"Report written: {txt_path}")
        return 0
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    sys.exit(main())