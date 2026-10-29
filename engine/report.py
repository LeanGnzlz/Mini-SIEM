import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from engine.alert import Alert
from engine.event import Event
from engine.rule import Rule

SEVERITY_ORDER = ("critical", "high", "medium", "low")


def to_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")
    return moment.astimezone(timezone.utc)


def report_basename(generated_at: datetime) -> str:
    return "siem_report_" + to_utc(generated_at).strftime("%Y%m%d_%H%M%S")


def build_report(
    events: list[Event],
    alerts: list[Alert],
    rejected: list[str],
    rules: list[Rule],
    generated_at: datetime,
) -> dict:
    events_by_id = {event.event_id: event for event in events}
    counts = Counter(alert.severity for alert in alerts)

    report_alerts = []
    for alert in alerts:
        try:
            evidence = [events_by_id[event_id].to_dict() for event_id in alert.event_ids]
        except KeyError as error:
            raise ValueError(
                f"alert {alert.alert_id} references unknown event {error}"
            ) from error
        entry = alert.to_dict()
        entry["evidence"] = evidence
        report_alerts.append(entry)

    return {
        "generated_at": to_utc(generated_at).isoformat(),
        "summary": {
            "events_ingested": len(events),
            "rejected_inputs": len(rejected),
            "rules_loaded": len(rules),
            "rules_enabled": sum(1 for rule in rules if rule.enabled),
            "alerts": len(alerts),
            "alerts_by_severity": {
                name: counts[name] for name in SEVERITY_ORDER if counts[name]
            },
        },
        "rejected": list(rejected),
        "alerts": report_alerts,
    }


RULE_LINE = "=" * 32


def format_time(text: str) -> str:
    moment = datetime.fromisoformat(text).astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def describe_event(item: dict) -> str:
    parts = [format_time(item["timestamp"]), item["event_type"], item["source"]]
    if item["src_ip"]:
        parts.append(f"src {item['src_ip']}")
    if item["dest_ip"] or item["dest_port"] is not None:
        host = item["dest_ip"] or "?"
        port = f":{item['dest_port']}" if item["dest_port"] is not None else ""
        parts.append(f"dest {host}{port}")
    if item["user"]:
        parts.append(f"user {item['user']}")
    return " | ".join(parts)


def format_alert_block(entry: dict) -> str:
    title = f"[{entry['severity'].upper()}] {entry['rule_id']} {entry['rule_name']}"
    if entry["mitre_technique"]:
        title += f" ({entry['mitre_technique']})"
    lines = [
        title,
        f"  Time: {format_time(entry['timestamp'])}",
        f"  {entry['description']}",
        f"  Evidence ({len(entry['evidence'])} event(s)):",
    ]
    lines.extend(f"    - {describe_event(item)}" for item in entry["evidence"])
    return "\n".join(lines)


def format_txt_report(report: dict) -> str:
    summary = report["summary"]
    severities = ", ".join(
        f"{name}: {count}" for name, count in summary["alerts_by_severity"].items()
    )
    alerts_line = f"  Alerts: {summary['alerts']}"
    if severities:
        alerts_line += f" ({severities})"

    lines = [
        RULE_LINE,
        "MINI-SIEM REPORT",
        RULE_LINE,
        f"Generated: {format_time(report['generated_at'])}",
        "",
        "Summary",
        f"  Events ingested: {summary['events_ingested']}",
        f"  Rejected inputs: {summary['rejected_inputs']}",
        f"  Rules loaded: {summary['rules_loaded']} ({summary['rules_enabled']} enabled)",
        alerts_line,
        "",
        "Alerts",
    ]
    if report["alerts"]:
        for entry in report["alerts"]:
            lines.append("")
            lines.append(format_alert_block(entry))
    else:
        lines.append("  No alerts.")

    lines.append("")
    lines.append("Rejected inputs")
    if report["rejected"]:
        lines.extend(f"  - {message}" for message in report["rejected"])
    else:
        lines.append("  None.")
    lines.extend(["", RULE_LINE])
    return "\n".join(lines) + "\n"


def write_new_file(directory, generated_at: datetime, extension: str, text: str) -> Path:
    name = f"{report_basename(generated_at)}.{extension}"
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    with open(path, "x", encoding="utf-8") as file:
        file.write(text)
    return path


def write_json_report(report: dict, directory, generated_at: datetime) -> Path:
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    return write_new_file(directory, generated_at, "json", text)


def write_txt_report(report: dict, directory, generated_at: datetime) -> Path:
    return write_new_file(directory, generated_at, "txt", format_txt_report(report))