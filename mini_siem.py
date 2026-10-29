import argparse
import sys
from collections import Counter
from datetime import timezone
from pathlib import Path

from engine.alert import Alert
from engine.evaluator import run_rules
from engine.ingest import ingest
from engine.rule import load_rules

DEFAULT_RULES = Path(__file__).resolve().parent / "rules" / "rules.yaml"
SEVERITY_ORDER = ("critical", "high", "medium", "low")


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
    return parser


def format_alert(alert: Alert) -> str:
    title = f"[{alert.severity.upper()}] {alert.rule_id} {alert.rule_name}"
    if alert.mitre_technique:
        title += f" ({alert.mitre_technique})"
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


def main(argv=None) -> int:
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
        events, rejected = ingest(
            scan_report_paths=args.scan,
            auth_log_paths=args.auth_log,
        )
    except (OSError, UnicodeDecodeError) as error:
        print(f"error: cannot read input: {error}", file=sys.stderr)
        return 2

    for message in rejected:
        print(f"warning: rejected input: {message}", file=sys.stderr)

    alerts = run_rules(rules, events)
    enabled = sum(1 for rule in rules if rule.enabled)

    print("Mini-SIEM")
    print(f"Events ingested: {len(events)}")
    print(f"Rejected inputs: {len(rejected)}")
    print(f"Rules loaded: {len(rules)} ({enabled} enabled)")
    if alerts:
        print(f"Alerts: {len(alerts)} ({severity_breakdown(alerts)})")
    else:
        print("Alerts: 0")
    for alert in alerts:
        print()
        print(format_alert(alert))
    return 0


if __name__ == "__main__":
    sys.exit(main())