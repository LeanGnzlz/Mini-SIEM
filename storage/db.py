import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    src_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER CHECK (dest_port IS NULL OR dest_port BETWEEN 0 AND 65535),
    user TEXT,
    severity_raw TEXT,
    raw_data TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    timestamp TEXT NOT NULL,
    description TEXT NOT NULL,
    mitre_technique TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id TEXT NOT NULL REFERENCES alerts (alert_id),
    event_id TEXT NOT NULL REFERENCES events (event_id),
    position INTEGER NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);
"""


def connect(path) -> sqlite3.Connection:
    location = str(path)
    if location != ":memory:":
        Path(location).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(location)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        connection.close()
        raise ValueError(
            f"database schema version {version} is newer than "
            f"the supported version {SCHEMA_VERSION}"
        )
    connection.executescript(SCHEMA)
    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    connection.commit()
    return connection