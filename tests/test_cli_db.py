import json
import sqlite3
from datetime import datetime, timezone

import pytest

import mini_siem
from engine.alert import Alert
from mini_siem import alerts_line, format_alert, main
from storage.db import connect

FIXED_NOW = datetime(2026, 10, 29, 19, 56, 0, tzinfo=timezone.utc)
JSON_NAME = "siem_report_20261029_195600.json"

FIVE_FAILURES = [
    "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:17 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:20 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:22 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:25 | FAILED_LOGIN | admin | 185.23.44.10",
]

SUCCESS_LINE = "2026-06-26 10:02:00 | SUCCESS_LOGIN | admin | 185.23.44.10"

FIVE_FAILURES_THEN_SUCCESS = FIVE_FAILURES + [SUCCESS_LINE]

GARBAGE = ["this is not a log line"]


def fixed_clock():
    return FIXED_NOW


def write_log(tmp_path, name, lines):
    folder = tmp_path / name
    folder.mkdir()
    path = folder / "auth.log"
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def database(tmp_path):
    return tmp_path / "siem.db"


def run(tmp_path, name, lines, *extra, use_db=True):
    args = ["--auth-log", write_log(tmp_path, name, lines)]
    if use_db:
        args += ["--db", str(database(tmp_path))]
    return main(args + list(extra), now=fixed_clock)


def saved_line(db, events_new, alerts_new, events_old, alerts_old):
    return (
        f"Saved to {db}: {events_new} new event(s), {alerts_new} new alert(s) "
        f"({events_old} event(s) and {alerts_old} alert(s) already stored)"
    )


def make_alert(severity="high"):
    return Alert(
        rule_id="R001",
        rule_name="Brute force",
        severity=severity,
        timestamp=datetime(2026, 6, 26, 13, 1, 25, tzinfo=timezone.utc),
        description="5 failed logins",
        event_ids=("e1",),
        mitre_technique="T1110.001",
    )


def track_connections(monkeypatch):
    opened = []
    real_connect = mini_siem.connect

    def tracking_connect(path):
        connection = real_connect(path)
        opened.append(connection)
        return connection

    monkeypatch.setattr(mini_siem, "connect", tracking_connect)
    return opened


def fail_saving(monkeypatch):
    def failing_save(connection, events, alerts):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(mini_siem, "save_run", failing_save)


def is_closed(connection):
    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return True
    return False


def insert_damaged_event(tmp_path):
    setup = connect(database(tmp_path))
    setup.execute(
        "INSERT INTO events (event_id, timestamp, source, event_type) "
        "VALUES ('bad1', '2026-06-26T10:00:00+00:00', '', 'auth_failure')"
    )
    setup.commit()
    setup.close()


def test_without_db_the_output_has_no_history_lines(tmp_path, capsys):
    code = run(tmp_path, "day1", FIVE_FAILURES, use_db=False)
    out, err = capsys.readouterr()
    lines = out.splitlines()
    assert code == 0
    assert "Alerts: 1 (medium: 1)" in lines
    assert "[MEDIUM] R002 Brute force (T1110.001)" in lines
    assert "[NEW]" not in out
    assert "History:" not in out
    assert "Events analyzed" not in out
    assert "Saved to" not in out
    assert not database(tmp_path).exists()


def test_first_run_with_db_marks_everything_as_new(tmp_path, capsys):
    code = run(tmp_path, "day1", FIVE_FAILURES)
    out, err = capsys.readouterr()
    lines = out.splitlines()
    db = database(tmp_path)
    assert code == 0
    assert err == ""
    assert "Events ingested: 5" in lines
    assert f"History: 0 event(s) loaded from {db}" in lines
    assert "Events analyzed: 5" in lines
    assert "Alerts: 1 (medium: 1), 1 new" in lines
    assert "[MEDIUM] R002 Brute force (T1110.001) [NEW]" in lines


def test_the_first_run_reports_what_it_saved(tmp_path, capsys):
    run(tmp_path, "day1", FIVE_FAILURES)
    lines = capsys.readouterr().out.splitlines()
    assert saved_line(database(tmp_path), 5, 1, 0, 0) in lines


def test_the_same_file_again_finds_nothing_new(tmp_path, capsys):
    run(tmp_path, "day1", FIVE_FAILURES)
    capsys.readouterr()
    code = run(tmp_path, "day2", FIVE_FAILURES)
    out, err = capsys.readouterr()
    lines = out.splitlines()
    db = database(tmp_path)
    assert code == 0
    assert f"History: 5 event(s) loaded from {db}" in lines
    assert "Events analyzed: 5" in lines
    assert "Alerts: 1 (medium: 1), 0 new" in lines
    assert "[MEDIUM] R002 Brute force (T1110.001)" in lines
    assert "[NEW]" not in out
    assert saved_line(db, 0, 0, 5, 1) in lines


def test_a_growing_log_marks_only_the_new_alert(tmp_path, capsys):
    run(tmp_path, "day1", FIVE_FAILURES)
    capsys.readouterr()
    run(tmp_path, "day2", FIVE_FAILURES_THEN_SUCCESS)
    out, err = capsys.readouterr()
    lines = out.splitlines()
    db = database(tmp_path)
    titles = [line for line in lines if line.startswith("[")]
    assert titles == [
        "[MEDIUM] R002 Brute force (T1110.001)",
        "[HIGH] R003 Successful brute force (T1110) [NEW]",
    ]
    assert "Events ingested: 6" in lines
    assert f"History: 5 event(s) loaded from {db}" in lines
    assert "Events analyzed: 6" in lines
    assert "Alerts: 2 (high: 1, medium: 1), 1 new" in lines
    assert saved_line(db, 1, 1, 5, 1) in lines


def test_a_pattern_across_two_runs_is_detected(tmp_path, capsys):
    run(tmp_path, "day1", FIVE_FAILURES)
    capsys.readouterr()
    run(tmp_path, "day2", [SUCCESS_LINE])
    out, err = capsys.readouterr()
    lines = out.splitlines()
    db = database(tmp_path)
    assert "Events ingested: 1" in lines
    assert f"History: 5 event(s) loaded from {db}" in lines
    assert "Events analyzed: 6" in lines
    assert "Alerts: 2 (high: 1, medium: 1), 1 new" in lines
    assert "[HIGH] R003 Successful brute force (T1110) [NEW]" in lines
    assert "[MEDIUM] R002 Brute force (T1110.001)" in lines
    assert saved_line(db, 1, 1, 0, 1) in lines


def test_the_second_file_alone_has_no_alerts_without_db(tmp_path, capsys):
    code = run(tmp_path, "day2", [SUCCESS_LINE], use_db=False)
    out, err = capsys.readouterr()
    assert code == 0
    assert "Alerts: 0" in out.splitlines()


def test_a_file_with_nothing_valid_still_shows_the_history_alerts(tmp_path, capsys):
    run(tmp_path, "day1", FIVE_FAILURES)
    capsys.readouterr()
    code = run(tmp_path, "day2", GARBAGE)
    out, err = capsys.readouterr()
    lines = out.splitlines()
    db = database(tmp_path)
    assert code == 0
    assert "Events ingested: 0" in lines
    assert "Rejected inputs: 1" in lines
    assert f"History: 5 event(s) loaded from {db}" in lines
    assert "Alerts: 1 (medium: 1), 0 new" in lines
    assert saved_line(db, 0, 0, 0, 1) in lines
    assert "warning: rejected input" in err


def test_the_database_folder_is_created(tmp_path):
    path = tmp_path / "nested" / "deeper" / "siem.db"
    log = write_log(tmp_path, "day1", FIVE_FAILURES)
    code = main(["--auth-log", log, "--db", str(path)], now=fixed_clock)
    assert code == 0
    assert path.exists()


def test_the_database_holds_the_saved_data(tmp_path):
    run(tmp_path, "day1", FIVE_FAILURES)
    raw = sqlite3.connect(str(database(tmp_path)))
    counts = [
        raw.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("events", "alerts", "alert_events")
    ]
    raw.close()
    assert counts == [5, 1, 5]


def test_rejected_lines_still_go_to_stderr_with_db(tmp_path, capsys):
    code = run(tmp_path, "day1", [FIVE_FAILURES[0], "garbage"])
    out, err = capsys.readouterr()
    assert code == 0
    assert "Rejected inputs: 1" in out.splitlines()
    assert "warning: rejected input: auth.log: line 2" in err
    assert "warning" not in out


def test_db_without_a_value_is_a_usage_error(tmp_path, capsys):
    log = write_log(tmp_path, "day1", FIVE_FAILURES)
    with pytest.raises(SystemExit) as info:
        main(["--auth-log", log, "--db"])
    assert info.value.code == 2
    assert "expected one argument" in capsys.readouterr().err


def test_a_directory_as_database_returns_2(tmp_path, capsys):
    log = write_log(tmp_path, "day1", FIVE_FAILURES)
    code = main(["--auth-log", log, "--db", str(tmp_path)], now=fixed_clock)
    out, err = capsys.readouterr()
    assert code == 2
    assert "cannot use database" in err
    assert out == ""


def test_a_file_that_is_not_a_database_returns_2(tmp_path, capsys):
    path = tmp_path / "fake.db"
    original = "this is not a database, just some text " * 10
    path.write_text(original, encoding="utf-8")
    log = write_log(tmp_path, "day1", FIVE_FAILURES)
    code = main(["--auth-log", log, "--db", str(path)], now=fixed_clock)
    out, err = capsys.readouterr()
    assert code == 2
    assert "cannot use database" in err
    assert out == ""
    assert path.read_text(encoding="utf-8") == original


def test_a_newer_database_returns_2(tmp_path, capsys):
    path = database(tmp_path)
    raw = sqlite3.connect(str(path))
    raw.execute("CREATE TABLE marker (x INTEGER)")
    raw.execute("PRAGMA user_version = 99")
    raw.commit()
    raw.close()
    log = write_log(tmp_path, "day1", FIVE_FAILURES)
    code = main(["--auth-log", log, "--db", str(path)], now=fixed_clock)
    out, err = capsys.readouterr()
    assert code == 2
    assert "cannot use database" in err
    assert "newer" in err
    assert out == ""


def test_a_damaged_database_returns_2(tmp_path, capsys):
    insert_damaged_event(tmp_path)
    code = run(tmp_path, "day1", FIVE_FAILURES)
    out, err = capsys.readouterr()
    assert code == 2
    assert "cannot use database" in err
    assert "event bad1 in the database is invalid" in err
    assert out == ""


def test_a_failed_save_returns_2_after_showing_the_alerts(tmp_path, capsys, monkeypatch):
    fail_saving(monkeypatch)
    reports = tmp_path / "reports"
    code = run(tmp_path, "day1", FIVE_FAILURES, "--report-dir", str(reports))
    out, err = capsys.readouterr()
    lines = out.splitlines()
    assert code == 2
    assert "Alerts: 1 (medium: 1), 1 new" in lines
    assert "[MEDIUM] R002 Brute force (T1110.001) [NEW]" in lines
    assert "Saved to" not in out
    assert "cannot save to database" in err
    assert not reports.exists()


def test_the_connection_is_closed_after_a_normal_run(tmp_path, monkeypatch):
    opened = track_connections(monkeypatch)
    assert run(tmp_path, "day1", FIVE_FAILURES) == 0
    assert len(opened) == 1
    assert is_closed(opened[0])


def test_the_connection_is_closed_after_a_failed_save(tmp_path, monkeypatch):
    opened = track_connections(monkeypatch)
    fail_saving(monkeypatch)
    assert run(tmp_path, "day1", FIVE_FAILURES) == 2
    assert len(opened) == 1
    assert is_closed(opened[0])


def test_the_connection_is_closed_after_damaged_data(tmp_path, monkeypatch):
    insert_damaged_event(tmp_path)
    opened = track_connections(monkeypatch)
    assert run(tmp_path, "day1", FIVE_FAILURES) == 2
    assert len(opened) == 1
    assert is_closed(opened[0])


def test_reports_include_the_history_evidence(tmp_path, capsys):
    run(tmp_path, "day1", FIVE_FAILURES)
    capsys.readouterr()
    reports = tmp_path / "reports"
    code = run(tmp_path, "day2", [SUCCESS_LINE], "--report-dir", str(reports))
    out, err = capsys.readouterr()
    data = json.loads((reports / JSON_NAME).read_text(encoding="utf-8"))
    compromise = data["alerts"][1]
    evidence_types = [item["event_type"] for item in compromise["evidence"]]
    assert code == 0
    assert data["summary"]["events_ingested"] == 6
    assert data["summary"]["alerts"] == 2
    assert compromise["rule_id"] == "R003"
    assert evidence_types == ["auth_failure"] * 5 + ["auth_success"]
    assert out.index("Saved to") < out.index("Report written")


def test_format_alert_marks_new_alerts():
    text = format_alert(make_alert(), is_new=True)
    assert text.splitlines()[0] == "[HIGH] R001 Brute force (T1110.001) [NEW]"


def test_format_alert_is_unchanged_by_default():
    text = format_alert(make_alert())
    assert text.splitlines()[0] == "[HIGH] R001 Brute force (T1110.001)"
    assert "[NEW]" not in format_alert(make_alert(), is_new=False)


def test_alerts_line_without_alerts():
    assert alerts_line([], None) == "Alerts: 0"
    assert alerts_line([], 0) == "Alerts: 0"


def test_alerts_line_without_a_database():
    alerts = [make_alert(), make_alert("medium")]
    assert alerts_line(alerts, None) == "Alerts: 2 (high: 1, medium: 1)"


def test_alerts_line_with_a_database():
    alerts = [make_alert(), make_alert("medium")]
    assert alerts_line(alerts, 1) == "Alerts: 2 (high: 1, medium: 1), 1 new"
    assert alerts_line([make_alert()], 0) == "Alerts: 1 (high: 1), 0 new"