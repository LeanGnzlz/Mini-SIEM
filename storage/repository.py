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


SELECT_EVENTS = (
    "SELECT event_id, timestamp, source, event_type, src_ip, dest_ip, "
    "dest_port, user, severity_raw, raw_data FROM events "
    "ORDER BY timestamp, rowid"
)
SELECT_ALERTS = (
    "SELECT alert_id, rule_id, rule_name, severity, timestamp, description, "
    "mitre_technique FROM alerts ORDER BY timestamp, rowid"
)
SELECT_EVIDENCE = (
    "SELECT alert_id, event_id FROM alert_events ORDER BY alert_id, position"
)


def parse_utc(text: str) -> datetime:
    return datetime.fromisoformat(text)


def row_to_event(row: sqlite3.Row) -> Event:
    try:
        return Event(
            event_id=row["event_id"],
            timestamp=parse_utc(row["timestamp"]),
            source=row["source"],
            event_type=row["event_type"],
            src_ip=row["src_ip"],
            dest_ip=row["dest_ip"],
            dest_port=row["dest_port"],
            user=row["user"],
            severity_raw=row["severity_raw"],
            raw_data=row["raw_data"],
        )
    except ValueError as error:
        raise ValueError(
            f"event {row['event_id']} in the database is invalid: {error}"
        ) from error


def load_events(connection: sqlite3.Connection) -> list[Event]:
    return [row_to_event(row) for row in connection.execute(SELECT_EVENTS)]


def load_alerts(connection: sqlite3.Connection) -> list[Alert]:
    evidence = {}
    for row in connection.execute(SELECT_EVIDENCE):
        evidence.setdefault(row["alert_id"], []).append(row["event_id"])

    alerts = []
    for row in connection.execute(SELECT_ALERTS):
        try:
            alerts.append(
                Alert(
                    alert_id=row["alert_id"],
                    rule_id=row["rule_id"],
                    rule_name=row["rule_name"],
                    severity=row["severity"],
                    timestamp=parse_utc(row["timestamp"]),
                    description=row["description"],
                    event_ids=tuple(evidence.get(row["alert_id"], ())),
                    mitre_technique=row["mitre_technique"],
                )
            )
        except ValueError as error:
            raise ValueError(
                f"alert {row['alert_id']} in the database is invalid: {error}"
            ) from error
    return alerts


SELECT_ALERT_IDS = "SELECT alert_id FROM alerts"


def load_alert_ids(connection: sqlite3.Connection) -> set[str]:
    return {row["alert_id"] for row in connection.execute(SELECT_ALERT_IDS)}