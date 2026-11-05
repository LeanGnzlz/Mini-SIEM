import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from engine.alert import Alert
from engine.event import Event

INSERT_EVENT = (
    "INSERT OR IGNORE INTO events (event_id, timestamp, source, event_type, "
    "src_ip, dest_ip, dest_port, user, severity_raw, raw_data) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
INSERT_ALERT = (
    "INSERT OR IGNORE INTO alerts (alert_id, rule_id, rule_name, severity, "
    "timestamp, description, mitre_technique) VALUES (?, ?, ?, ?, ?, ?, ?)"
)
INSERT_LINK = (
    "INSERT INTO alert_events (alert_id, event_id, position) VALUES (?, ?, ?)"
)


@dataclass(frozen=True)
class SaveResult:
    events_new: int
    events_existing: int
    alerts_new: int
    alerts_existing: int


def utc_text(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def event_row(event: Event) -> tuple:
    return (
        event.event_id,
        utc_text(event.timestamp),
        event.source,
        event.event_type,
        event.src_ip,
        event.dest_ip,
        event.dest_port,
        event.user,
        event.severity_raw,
        event.raw_data,
    )


def alert_row(alert: Alert) -> tuple:
    return (
        alert.alert_id,
        alert.rule_id,
        alert.rule_name,
        alert.severity,
        utc_text(alert.timestamp),
        alert.description,
        alert.mitre_technique,
    )


def save_run(
    connection: sqlite3.Connection,
    events: list[Event],
    alerts: list[Alert],
) -> SaveResult:
    events_new = 0
    alerts_new = 0
    with connection:
        for event in events:
            events_new += connection.execute(INSERT_EVENT, event_row(event)).rowcount
        for alert in alerts:
            inserted = connection.execute(INSERT_ALERT, alert_row(alert)).rowcount
            if inserted:
                alerts_new += 1
                for position, event_id in enumerate(alert.event_ids):
                    connection.execute(INSERT_LINK, (alert.alert_id, event_id, position))
    return SaveResult(
        events_new=events_new,
        events_existing=len(events) - events_new,
        alerts_new=alerts_new,
        alerts_existing=len(alerts) - alerts_new,
    )