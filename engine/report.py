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


def write_json_report(report: dict, directory, generated_at: datetime) -> Path:
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{report_basename(generated_at)}.json"
    with open(path, "x", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)
        file.write("\n")
    return path