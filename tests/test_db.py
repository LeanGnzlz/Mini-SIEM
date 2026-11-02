import sqlite3

import pytest

from storage.db import SCHEMA_VERSION, connect

HOSTILE_VALUES = [
    "x'; DROP TABLE events; --",
    "' OR '1'='1",
    'Robert"); DROP TABLE alerts; --',
]


@pytest.fixture
def db():
    connection = connect(":memory:")
    yield connection
    connection.close()


def object_names(connection, kind):
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type = ?", (kind,))
    return {row["name"] for row in rows}


def insert_event(connection, event_id="e1", **overrides):
    values = dict(
        event_id=event_id,
        timestamp="2026-06-26T13:01:15+00:00",
        source="login_failure_detector",
        event_type="auth_failure",
        src_ip="185.23.44.10",
        dest_ip=None,
        dest_port=None,
        user="admin",
        severity_raw=None,
        raw_data="original line",
    )
    values.update(overrides)
    connection.execute(
        "INSERT INTO events (event_id, timestamp, source, event_type, src_ip, "
        "dest_ip, dest_port, user, severity_raw, raw_data) "
        "VALUES (:event_id, :timestamp, :source, :event_type, :src_ip, "
        ":dest_ip, :dest_port, :user, :severity_raw, :raw_data)",
        values,
    )


def insert_alert(connection, alert_id="a1", **overrides):
    values = dict(
        alert_id=alert_id,
        rule_id="R002",
        rule_name="Brute force",
        severity="medium",
        timestamp="2026-06-26T13:01:25+00:00",
        description="5 failed logins",
        mitre_technique="T1110.001",
    )
    values.update(overrides)
    connection.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_name, severity, timestamp, "
        "description, mitre_technique) "
        "VALUES (:alert_id, :rule_id, :rule_name, :severity, :timestamp, "
        ":description, :mitre_technique)",
        values,
    )


def link(connection, alert_id, event_id, position=0):
    connection.execute(
        "INSERT INTO alert_events (alert_id, event_id, position) VALUES (?, ?, ?)",
        (alert_id, event_id, position),
    )


def count(connection, table):
    return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def make_future_database(tmp_path):
    path = tmp_path / "future.db"
    raw = sqlite3.connect(str(path))
    raw.execute("CREATE TABLE marker (x INTEGER)")
    raw.execute("PRAGMA user_version = 99")
    raw.commit()
    raw.close()
    return path


def test_connect_creates_the_tables(db):
    assert {"events", "alerts", "alert_events"} <= object_names(db, "table")


def test_connect_creates_the_timestamp_indexes(db):
    assert {"idx_events_timestamp", "idx_alerts_timestamp"} <= object_names(db, "index")


def test_connect_records_the_schema_version(db):
    assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_foreign_keys_are_enabled(db):
    assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_rows_can_be_read_by_column_name(db):
    insert_event(db)
    row = db.execute("SELECT event_id, user FROM events").fetchone()
    assert row["event_id"] == "e1"
    assert row["user"] == "admin"


def test_reconnecting_keeps_the_data(tmp_path):
    path = tmp_path / "siem.db"
    first = connect(path)
    insert_event(first)
    first.commit()
    first.close()
    second = connect(path)
    assert count(second, "events") == 1
    assert second.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    second.close()


def test_missing_parent_directory_is_created(tmp_path):
    path = tmp_path / "nested" / "deeper" / "siem.db"
    connect(path).close()
    assert path.exists()


def test_in_memory_database_creates_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    connection = connect(":memory:")
    insert_event(connection)
    connection.close()
    assert list(tmp_path.iterdir()) == []


def test_database_from_a_newer_version_is_rejected(tmp_path):
    path = make_future_database(tmp_path)
    with pytest.raises(ValueError, match="newer"):
        connect(path)


def test_a_rejected_database_is_left_untouched(tmp_path):
    path = make_future_database(tmp_path)
    with pytest.raises(ValueError):
        connect(path)
    raw = sqlite3.connect(str(path))
    tables = {row[0] for row in raw.execute("SELECT name FROM sqlite_master")}
    version = raw.execute("PRAGMA user_version").fetchone()[0]
    raw.close()
    assert tables == {"marker"}
    assert version == 99


def test_event_is_saved_and_read_back(db):
    insert_event(db, dest_ip="127.0.0.1", dest_port=445)
    row = db.execute("SELECT * FROM events WHERE event_id = ?", ("e1",)).fetchone()
    assert row["dest_ip"] == "127.0.0.1"
    assert row["dest_port"] == 445
    assert row["raw_data"] == "original line"


def test_duplicate_event_id_is_rejected(db):
    insert_event(db)
    with pytest.raises(sqlite3.IntegrityError):
        insert_event(db)


def test_insert_or_ignore_keeps_a_single_row(db):
    sql = (
        "INSERT OR IGNORE INTO events (event_id, timestamp, source, event_type) "
        "VALUES (?, ?, ?, ?)"
    )
    row = ("e1", "2026-06-26T13:01:15+00:00", "login_failure_detector", "auth_failure")
    db.execute(sql, row)
    db.execute(sql, row)
    assert count(db, "events") == 1


@pytest.mark.parametrize("field", ["timestamp", "source", "event_type", "raw_data"])
def test_required_event_fields_cannot_be_null(db, field):
    with pytest.raises(sqlite3.IntegrityError):
        insert_event(db, **{field: None})


@pytest.mark.parametrize("port", [0, 65535, None])
def test_valid_ports_are_accepted(db, port):
    insert_event(db, dest_port=port)
    assert db.execute("SELECT dest_port FROM events").fetchone()["dest_port"] == port


@pytest.mark.parametrize("port", [-1, 65536, 70000])
def test_invalid_ports_are_rejected(db, port):
    with pytest.raises(sqlite3.IntegrityError):
        insert_event(db, dest_port=port)


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
def test_valid_severities_are_accepted(db, severity):
    insert_alert(db, severity=severity)
    assert db.execute("SELECT severity FROM alerts").fetchone()["severity"] == severity


@pytest.mark.parametrize("severity", ["HIGH", "gigantic", ""])
def test_invalid_severities_are_rejected(db, severity):
    with pytest.raises(sqlite3.IntegrityError):
        insert_alert(db, severity=severity)


def test_duplicate_alert_id_is_rejected(db):
    insert_alert(db)
    with pytest.raises(sqlite3.IntegrityError):
        insert_alert(db)


@pytest.mark.parametrize("field", ["rule_id", "rule_name", "timestamp", "description"])
def test_required_alert_fields_cannot_be_null(db, field):
    with pytest.raises(sqlite3.IntegrityError):
        insert_alert(db, **{field: None})


def test_alert_event_link_is_saved(db):
    insert_event(db)
    insert_alert(db)
    link(db, "a1", "e1")
    assert count(db, "alert_events") == 1


def test_link_to_a_missing_alert_is_rejected(db):
    insert_event(db)
    with pytest.raises(sqlite3.IntegrityError):
        link(db, "missing", "e1")


def test_link_to_a_missing_event_is_rejected(db):
    insert_alert(db)
    with pytest.raises(sqlite3.IntegrityError):
        link(db, "a1", "missing")


def test_duplicate_link_is_rejected(db):
    insert_event(db)
    insert_alert(db)
    link(db, "a1", "e1")
    with pytest.raises(sqlite3.IntegrityError):
        link(db, "a1", "e1")


def test_an_event_can_be_evidence_of_several_alerts(db):
    insert_event(db)
    insert_alert(db, "a1")
    insert_alert(db, "a2", rule_id="R004")
    link(db, "a1", "e1")
    link(db, "a2", "e1")
    rows = db.execute("SELECT alert_id FROM alert_events WHERE event_id = ?", ("e1",))
    assert len(rows.fetchall()) == 2


def test_an_alert_keeps_its_evidence_in_order(db):
    for event_id in ("e1", "e2", "e3"):
        insert_event(db, event_id)
    insert_alert(db)
    link(db, "a1", "e3", 2)
    link(db, "a1", "e1", 0)
    link(db, "a1", "e2", 1)
    rows = db.execute(
        "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY position",
        ("a1",),
    )
    assert [row["event_id"] for row in rows] == ["e1", "e2", "e3"]


def test_an_event_used_as_evidence_cannot_be_deleted(db):
    insert_event(db)
    insert_alert(db)
    link(db, "a1", "e1")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM events WHERE event_id = ?", ("e1",))


def test_an_alert_with_evidence_cannot_be_deleted(db):
    insert_event(db)
    insert_alert(db)
    link(db, "a1", "e1")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM alerts WHERE alert_id = ?", ("a1",))


@pytest.mark.parametrize("hostile", HOSTILE_VALUES)
def test_hostile_values_are_stored_as_plain_text(db, hostile):
    insert_event(db, user=hostile, raw_data=hostile)
    assert {"events", "alerts", "alert_events"} <= object_names(db, "table")
    assert count(db, "events") == 1
    row = db.execute("SELECT user, raw_data FROM events").fetchone()
    assert row["user"] == hostile
    assert row["raw_data"] == hostile


def test_a_hostile_search_value_only_matches_itself(db):
    hostile = "' OR '1'='1"
    insert_event(db, "e1", user="admin")
    insert_event(db, "e2", user=hostile)
    rows = db.execute("SELECT event_id FROM events WHERE user = ?", (hostile,))
    assert [row["event_id"] for row in rows] == ["e2"]


def test_demo_concatenated_query_is_injectable(db):
    hostile = "' OR '1'='1"
    insert_event(db, "e1", user="admin")
    insert_event(db, "e2", user="maria")
    unsafe_query = f"SELECT event_id FROM events WHERE user = '{hostile}'"
    assert len(db.execute(unsafe_query).fetchall()) == 2