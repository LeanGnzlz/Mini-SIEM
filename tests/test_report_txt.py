from datetime import datetime, timezone
from pathlib import Path

import pytest

from adapters.login_detector_adapter import parse_auth_log
from adapters.network_scanner_adapter import parse_scan_report
from engine.evaluator import run_rules
from engine.report import (
    build_report,
    describe_event,
    format_alert_block,
    format_time,
    format_txt_report,
    write_json_report,
    write_txt_report,
)
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


def evidence_item(**overrides):
    base = dict(
        timestamp="2026-06-26T13:01:25+00:00",
        source="login_failure_detector",
        event_type="auth_failure",
        src_ip="185.23.44.10",
        dest_ip=None,
        dest_port=None,
        user="admin",
    )
    base.update(overrides)
    return base


def alert_entry(**overrides):
    base = dict(
        rule_id="R003",
        rule_name="Successful brute force",
        severity="high",
        timestamp="2026-06-26T13:02:00+00:00",
        description="Failed logins followed by a login",
        mitre_technique="T1110",
        evidence=[
            evidence_item(),
            evidence_item(timestamp="2026-06-26T13:02:00+00:00", event_type="auth_success"),
        ],
    )
    base.update(overrides)
    return base


def small_report(alerts, rejected, by_severity):
    return {
        "generated_at": "2026-10-29T19:56:00+00:00",
        "summary": {
            "events_ingested": 3,
            "rejected_inputs": len(rejected),
            "rules_loaded": 2,
            "rules_enabled": 2,
            "alerts": len(alerts),
            "alerts_by_severity": by_severity,
        },
        "rejected": rejected,
        "alerts": alerts,
    }


def real_report():
    events = parse_scan_report(SCAN_WITH_SMB)
    parsed, rejected = parse_auth_log(LOG_WITH_COMPROMISE)
    assert rejected == []
    events.extend(parsed)
    rules = load_rules(RULES_PATH)
    alerts = run_rules(rules, events)
    return build_report(events, alerts, [], rules, GENERATED_AT)


def test_format_time_keeps_utc():
    assert format_time("2026-06-26T13:01:25+00:00") == "2026-06-26 13:01:25 UTC"


def test_format_time_converts_other_offsets():
    assert format_time("2026-06-26T10:01:25-03:00") == "2026-06-26 13:01:25 UTC"


def test_describe_login_event():
    assert describe_event(evidence_item()) == (
        "2026-06-26 13:01:25 UTC | auth_failure | login_failure_detector"
        " | src 185.23.44.10 | user admin"
    )


def test_describe_port_event():
    item = evidence_item(
        source="network_scanner",
        event_type="port_open",
        src_ip=None,
        user=None,
        dest_ip="127.0.0.1",
        dest_port=445,
    )
    assert describe_event(item) == (
        "2026-06-26 13:01:25 UTC | port_open | network_scanner | dest 127.0.0.1:445"
    )


def test_describe_event_with_port_but_no_destination_ip():
    item = evidence_item(src_ip=None, user=None, dest_port=445)
    assert describe_event(item).endswith(" | dest ?:445")


def test_describe_event_with_destination_ip_but_no_port():
    item = evidence_item(src_ip=None, user=None, dest_ip="127.0.0.1")
    assert describe_event(item).endswith(" | dest 127.0.0.1")


def test_port_zero_is_not_hidden():
    item = evidence_item(src_ip=None, user=None, dest_port=0)
    assert describe_event(item).endswith(" | dest ?:0")


def test_describe_event_with_only_the_required_fields():
    item = evidence_item(src_ip=None, user=None)
    assert describe_event(item) == (
        "2026-06-26 13:01:25 UTC | auth_failure | login_failure_detector"
    )


def test_alert_block_with_mitre():
    assert format_alert_block(alert_entry()).splitlines() == [
        "[HIGH] R003 Successful brute force (T1110)",
        "  Time: 2026-06-26 13:02:00 UTC",
        "  Failed logins followed by a login",
        "  Evidence (2 event(s)):",
        "    - 2026-06-26 13:01:25 UTC | auth_failure | login_failure_detector"
        " | src 185.23.44.10 | user admin",
        "    - 2026-06-26 13:02:00 UTC | auth_success | login_failure_detector"
        " | src 185.23.44.10 | user admin",
    ]


def test_alert_block_without_mitre():
    block = format_alert_block(alert_entry(mitre_technique=None))
    assert block.splitlines()[0] == "[HIGH] R003 Successful brute force"


def test_full_txt_report_exact_text():
    report = small_report([alert_entry()], ["auth.log: line 2: broken"], {"high": 1})
    expected = "\n".join(
        [
            "================================",
            "MINI-SIEM REPORT",
            "================================",
            "Generated: 2026-10-29 19:56:00 UTC",
            "",
            "Summary",
            "  Events ingested: 3",
            "  Rejected inputs: 1",
            "  Rules loaded: 2 (2 enabled)",
            "  Alerts: 1 (high: 1)",
            "",
            "Alerts",
            "",
            "[HIGH] R003 Successful brute force (T1110)",
            "  Time: 2026-06-26 13:02:00 UTC",
            "  Failed logins followed by a login",
            "  Evidence (2 event(s)):",
            "    - 2026-06-26 13:01:25 UTC | auth_failure | login_failure_detector"
            " | src 185.23.44.10 | user admin",
            "    - 2026-06-26 13:02:00 UTC | auth_success | login_failure_detector"
            " | src 185.23.44.10 | user admin",
            "",
            "Rejected inputs",
            "  - auth.log: line 2: broken",
            "",
            "================================",
        ]
    ) + "\n"
    assert format_txt_report(report) == expected


def test_report_without_alerts_and_without_rejections():
    lines = format_txt_report(small_report([], [], {})).splitlines()
    assert "  Alerts: 0" in lines
    assert "  No alerts." in lines
    assert "  None." in lines
    assert not any(line.startswith("[") for line in lines)


def test_severity_breakdown_follows_the_report_order():
    report = small_report([alert_entry()] * 3, [], {"critical": 1, "high": 2})
    lines = format_txt_report(report).splitlines()
    assert "  Alerts: 3 (critical: 1, high: 2)" in lines


def test_real_report_summary_and_alert_order():
    lines = format_txt_report(real_report()).splitlines()
    assert "  Events ingested: 15" in lines
    assert "  Rules loaded: 4 (4 enabled)" in lines
    assert "  Alerts: 5 (high: 2, medium: 3)" in lines
    assert "[HIGH] R001 Sensitive port open" in lines
    assert "[HIGH] R003 Successful brute force (T1110)" in lines
    titles = [line for line in lines if line.startswith("[")]
    assert [line.split()[1] for line in titles] == ["R001", "R002", "R003", "R002", "R004"]


def test_real_report_lists_every_piece_of_evidence():
    lines = format_txt_report(real_report()).splitlines()
    evidence_lines = [line for line in lines if line.startswith("    - ")]
    assert len(evidence_lines) == 22


def test_real_report_shows_event_details():
    text = format_txt_report(real_report())
    assert "dest 127.0.0.1:445" in text
    assert "src 185.23.44.10" in text
    assert "user admin" in text
    assert "port_open" in text


def test_real_report_leaves_the_raw_log_lines_out():
    text = format_txt_report(real_report())
    assert "FAILED_LOGIN" not in text
    assert "SUCCESS_LOGIN" not in text
    assert "Not applicable" not in text


def test_real_report_times_are_in_utc():
    lines = format_txt_report(real_report()).splitlines()
    time_lines = [line for line in lines if line.startswith("  Time:")]
    evidence_lines = [line for line in lines if line.startswith("    - ")]
    assert len(time_lines) == 5
    assert all(line.endswith(" UTC") for line in time_lines)
    assert all(" UTC | " in line for line in evidence_lines)


def test_write_txt_report_creates_the_file(tmp_path):
    report = small_report([alert_entry()], [], {"high": 1})
    path = write_txt_report(report, tmp_path, GENERATED_AT)
    assert path.parent == tmp_path
    assert path.name == "siem_report_20261029_195600.txt"
    assert path.read_text(encoding="utf-8") == format_txt_report(report)


def test_json_and_txt_of_the_same_run_share_the_name(tmp_path):
    report = small_report([], [], {})
    json_path = write_json_report(report, tmp_path, GENERATED_AT)
    txt_path = write_txt_report(report, tmp_path, GENERATED_AT)
    assert json_path.stem == txt_path.stem
    assert json_path.suffix == ".json"
    assert txt_path.suffix == ".txt"
    assert len(list(tmp_path.iterdir())) == 2


def test_an_existing_txt_report_is_never_overwritten(tmp_path):
    first = small_report([alert_entry()], [], {"high": 1})
    path = write_txt_report(first, tmp_path, GENERATED_AT)
    original = path.read_text(encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_txt_report(small_report([], [], {}), tmp_path, GENERATED_AT)
    assert path.read_text(encoding="utf-8") == original


def test_naive_datetime_is_rejected_before_touching_the_disk(tmp_path):
    folder = tmp_path / "new"
    with pytest.raises(ValueError, match="timezone-aware"):
        write_txt_report(small_report([], [], {}), folder, datetime(2026, 10, 29, 19, 56, 0))
    assert not folder.exists()


def test_unserializable_data_leaves_nothing_behind(tmp_path):
    folder = tmp_path / "new"
    with pytest.raises(TypeError):
        write_json_report({"bad": object()}, folder, GENERATED_AT)
    assert not folder.exists()


def test_accented_characters_are_written_correctly(tmp_path):
    report = small_report([], ["línea inválida de josé"], {})
    path = write_txt_report(report, tmp_path, GENERATED_AT)
    assert "línea inválida de josé" in path.read_text(encoding="utf-8")