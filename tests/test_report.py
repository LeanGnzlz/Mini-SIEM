import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from adapters.login_detector_adapter import parse_auth_log
from adapters.network_scanner_adapter import parse_scan_report
from engine.evaluator import run_rules
from engine.report import build_report, report_basename, write_json_report
from engine.rule import load_rules

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"
GENERATED_AT = datetime(2026, 10, 29, 19, 56, 0, tzinfo=timezone.utc)

SCAN_WITH_SMB = {
    "target": "127.0.0.1",
    "scan_duration": 21.21,
    "completed": "2026-06-25 13:58:39",
    "open_ports": [
        {"port": 135, "service": "MSRPC", "banner": "Not applicable"},
        {"port": 445, "service": "SMB", "banner": "Not applicable"},
    ],
}

LOG_WITH_COMPROMISE = [
    "2026-06-26 10:00:01 | SUCCESS_LOGIN | leandro | 192.168.1.20",
    "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:17 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:20 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:22 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:25 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:02:00 | SUCCESS_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:05:10 | SUCCESS_LOGIN | maria | 192.168.1.30",
    "2026-06-26 11:00:01 | FAILED_LOGIN | admin | 10.0.0.50",
    "2026-06-26 11:00:03 | FAILED_LOGIN | maria | 10.0.0.50",
    "2026-06-26 11:00:05 | FAILED_LOGIN | juan | 10.0.0.50",
    "2026-06-26 11:00:07 | FAILED_LOGIN | pedro | 10.0.0.50",
    "2026-06-26 11:00:09 | FAILED_LOGIN | carlos | 10.0.0.50",
]

NORMAL_LOG = [
    "2026-06-26 10:00:01 | SUCCESS_LOGIN | leandro | 192.168.1.20",
    "2026-06-26 10:05:10 | SUCCESS_LOGIN | maria | 192.168.1.30",
]


def scenario(scan_report=SCAN_WITH_SMB, log_lines=LOG_WITH_COMPROMISE):
    events = []
    if scan_report is not None:
        events.extend(parse_scan_report(scan_report))
    parsed, rejected = parse_auth_log(log_lines)
    assert rejected == []
    events.extend(parsed)
    rules = load_rules(RULES_PATH)
    return events, run_rules(rules, events), rules


def make_report(rejected=(), generated_at=GENERATED_AT, **kwargs):
    events, alerts, rules = scenario(**kwargs)
    return build_report(events, alerts, list(rejected), rules, generated_at)


def test_basename_uses_the_utc_time():
    assert report_basename(GENERATED_AT) == "siem_report_20261029_195600"


def test_basename_converts_other_time_zones_to_utc():
    argentina = timezone(timedelta(hours=-3))
    moment = datetime(2026, 10, 29, 16, 56, 0, tzinfo=argentina)
    assert report_basename(moment) == "siem_report_20261029_195600"


def test_basename_rejects_a_naive_datetime():
    with pytest.raises(ValueError, match="timezone-aware"):
        report_basename(datetime(2026, 10, 29, 19, 56, 0))


def test_build_report_rejects_a_naive_datetime():
    with pytest.raises(ValueError, match="timezone-aware"):
        build_report([], [], [], [], datetime(2026, 10, 29, 19, 56, 0))


def test_generated_at_is_written_in_utc():
    assert make_report()["generated_at"] == "2026-10-29T19:56:00+00:00"


def test_summary_counts_everything():
    report = make_report(rejected=["auth.log: line 2: broken"])
    assert report["summary"] == {
        "events_ingested": 15,
        "rejected_inputs": 1,
        "rules_loaded": 4,
        "rules_enabled": 4,
        "alerts": 5,
        "alerts_by_severity": {"high": 2, "medium": 3},
    }


def test_severities_are_listed_from_most_severe():
    counts = make_report()["summary"]["alerts_by_severity"]
    assert list(counts) == ["high", "medium"]


def test_alerts_keep_the_engine_order():
    rule_ids = [entry["rule_id"] for entry in make_report()["alerts"]]
    assert rule_ids == ["R001", "R002", "R003", "R002", "R004"]


def test_evidence_matches_the_event_ids_of_every_alert():
    for entry in make_report()["alerts"]:
        evidence_ids = [item["event_id"] for item in entry["evidence"]]
        assert evidence_ids == entry["event_ids"]


def test_port_alert_evidence_has_the_full_event_detail():
    entry = make_report()["alerts"][0]
    assert entry["rule_id"] == "R001"
    assert len(entry["evidence"]) == 1
    evidence = entry["evidence"][0]
    assert evidence["source"] == "network_scanner"
    assert evidence["event_type"] == "port_open"
    assert evidence["dest_ip"] == "127.0.0.1"
    assert evidence["dest_port"] == 445
    assert json.loads(evidence["raw_data"])["service"] == "SMB"


def test_compromise_alert_evidence_lists_the_failures_then_the_success():
    entry = make_report()["alerts"][2]
    assert entry["rule_id"] == "R003"
    types = [item["event_type"] for item in entry["evidence"]]
    assert types == ["auth_failure"] * 5 + ["auth_success"]
    assert {item["src_ip"] for item in entry["evidence"]} == {"185.23.44.10"}
    assert entry["evidence"][0]["user"] == "admin"


def test_rejected_inputs_are_listed():
    report = make_report(rejected=["auth.log: line 2: broken"])
    assert report["rejected"] == ["auth.log: line 2: broken"]


def test_the_report_keeps_its_own_copy_of_the_rejected_list():
    rejected = ["auth.log: line 2: broken"]
    events, alerts, rules = scenario()
    report = build_report(events, alerts, rejected, rules, GENERATED_AT)
    rejected.append("auth.log: line 9: another")
    assert report["rejected"] == ["auth.log: line 2: broken"]


def test_alert_with_unknown_evidence_is_rejected():
    events, alerts, rules = scenario()
    with pytest.raises(ValueError, match="unknown event"):
        build_report(events[:1], alerts, [], rules, GENERATED_AT)


def test_report_without_alerts():
    report = make_report(scan_report=None, log_lines=NORMAL_LOG)
    assert report["summary"]["events_ingested"] == 2
    assert report["summary"]["alerts"] == 0
    assert report["summary"]["alerts_by_severity"] == {}
    assert report["alerts"] == []


def test_report_survives_a_json_round_trip():
    report = make_report(rejected=["auth.log: line 2: broken"])
    assert json.loads(json.dumps(report)) == report


def test_write_json_report_creates_the_file_with_the_expected_name(tmp_path):
    report = make_report()
    path = write_json_report(report, tmp_path, GENERATED_AT)
    assert path.parent == tmp_path
    assert path.name == "siem_report_20261029_195600.json"
    assert json.loads(path.read_text(encoding="utf-8")) == report


def test_write_json_report_creates_a_missing_directory(tmp_path):
    folder = tmp_path / "nested" / "reports"
    path = write_json_report({"ok": True}, folder, GENERATED_AT)
    assert folder.is_dir()
    assert path.exists()


def test_an_existing_report_is_never_overwritten(tmp_path):
    path = write_json_report(make_report(), tmp_path, GENERATED_AT)
    original = path.read_text(encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_json_report({"other": 1}, tmp_path, GENERATED_AT)
    assert path.read_text(encoding="utf-8") == original


def test_reports_from_different_seconds_are_kept_separately(tmp_path):
    write_json_report({"run": 1}, tmp_path, GENERATED_AT)
    write_json_report({"run": 2}, tmp_path, GENERATED_AT + timedelta(seconds=1))
    assert len(list(tmp_path.iterdir())) == 2


def test_the_file_is_indented_and_ends_with_a_newline(tmp_path):
    path = write_json_report(make_report(), tmp_path, GENERATED_AT)
    text = path.read_text(encoding="utf-8")
    assert text.startswith('{\n  "generated_at"')
    assert text.endswith("}\n")


def test_accented_characters_stay_readable(tmp_path):
    path = write_json_report({"user": "josé"}, tmp_path, GENERATED_AT)
    text = path.read_text(encoding="utf-8")
    assert "josé" in text
    assert "\\u00e9" not in text


def test_write_json_report_rejects_a_naive_datetime(tmp_path):
    with pytest.raises(ValueError, match="timezone-aware"):
        write_json_report({"ok": True}, tmp_path, datetime(2026, 10, 29, 19, 56, 0))