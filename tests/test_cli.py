import json
from datetime import datetime, timedelta, timezone

import pytest

from engine.alert import Alert
from mini_siem import format_alert, main, severity_breakdown

SCAN_REPORT = {
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

FOUR_FAILURES_LOG = [
    "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:17 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:20 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:22 | FAILED_LOGIN | admin | 185.23.44.10",
]


def write_scan(tmp_path, name="scan.json"):
    path = tmp_path / name
    path.write_text(json.dumps(SCAN_REPORT), encoding="utf-8")
    return str(path)


def write_log(tmp_path, lines, name="auth.log"):
    path = tmp_path / name
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def write_text(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def make_alert(severity="high", **overrides):
    base = dict(
        rule_id="R001",
        rule_name="Brute force",
        severity=severity,
        timestamp=datetime(2026, 6, 26, 13, 1, 25, tzinfo=timezone.utc),
        description="5 failed logins",
        event_ids=("event-1", "event-2"),
        mitre_technique="T1110.001",
    )
    base.update(overrides)
    return Alert(**base)


def test_full_run_prints_summary_and_alerts(tmp_path, capsys):
    code = main(
        [
            "--scan",
            write_scan(tmp_path),
            "--auth-log",
            write_log(tmp_path, LOG_WITH_COMPROMISE),
        ]
    )
    out, err = capsys.readouterr()
    assert code == 0
    assert "Events ingested: 15" in out
    assert "Rejected inputs: 0" in out
    assert "Rules loaded: 4 (4 enabled)" in out
    assert "Alerts: 5 (high: 2, medium: 3)" in out
    assert "[HIGH] R003 Successful brute force (T1110)" in out
    assert "[MEDIUM] R004 Password spraying (T1110.003)" in out
    assert "[HIGH] R001 Sensitive port open\n" in out
    assert err == ""


def test_alerts_are_listed_in_time_order(tmp_path, capsys):
    main(
        [
            "--scan",
            write_scan(tmp_path),
            "--auth-log",
            write_log(tmp_path, LOG_WITH_COMPROMISE),
        ]
    )
    out = capsys.readouterr().out
    titles = [line for line in out.splitlines() if line.startswith("[")]
    assert [line.split()[1] for line in titles] == ["R001", "R002", "R003", "R002", "R004"]


def test_alert_blocks_show_description_and_evidence(tmp_path, capsys):
    main(
        [
            "--scan",
            write_scan(tmp_path),
            "--auth-log",
            write_log(tmp_path, LOG_WITH_COMPROMISE),
        ]
    )
    out = capsys.readouterr().out
    assert "Remote access or file sharing port found open" in out
    assert (
        "Failed logins followed by a successful login from the same IP: "
        "src_ip=185.23.44.10, sequence auth_failure x5 -> auth_success within 300s"
    ) in out
    assert "  Evidence: 6 event(s)" in out
    assert "  Evidence: 1 event(s)" in out
    time_lines = [line for line in out.splitlines() if line.startswith("  Time:")]
    assert len(time_lines) == 5
    assert all(line.endswith(" UTC") for line in time_lines)


def test_run_without_alerts(tmp_path, capsys):
    code = main(["--auth-log", write_log(tmp_path, NORMAL_LOG)])
    out, err = capsys.readouterr()
    assert code == 0
    assert "Events ingested: 2" in out
    assert "Alerts: 0" in out
    assert not [line for line in out.splitlines() if line.startswith("[")]
    assert err == ""


def test_rejected_lines_go_to_stderr(tmp_path, capsys):
    lines = [FOUR_FAILURES_LOG[0], "this is not a log line"]
    code = main(["--auth-log", write_log(tmp_path, lines)])
    out, err = capsys.readouterr()
    assert code == 0
    assert "Events ingested: 1" in out
    assert "Rejected inputs: 1" in out
    assert "warning: rejected input: auth.log: line 2" in err
    assert "warning" not in out


def test_broken_scan_report_is_reported_and_logs_still_run(tmp_path, capsys):
    broken = write_text(tmp_path, "broken.json", "{ not json")
    log = write_log(tmp_path, LOG_WITH_COMPROMISE)
    code = main(["--scan", broken, "--auth-log", log])
    out, err = capsys.readouterr()
    assert code == 0
    assert "Events ingested: 13" in out
    assert "Rejected inputs: 1" in out
    assert "warning: rejected input: broken.json" in err


def test_multiple_files_per_option(tmp_path, capsys):
    first = write_log(tmp_path, FOUR_FAILURES_LOG, name="first.log")
    second = write_log(tmp_path, NORMAL_LOG, name="second.log")
    code = main(["--auth-log", first, second])
    out = capsys.readouterr().out
    assert code == 0
    assert "Events ingested: 6" in out
    assert "Alerts: 0" in out


def test_missing_input_file_returns_2(tmp_path, capsys):
    code = main(["--auth-log", str(tmp_path / "nope.log")])
    out, err = capsys.readouterr()
    assert code == 2
    assert "cannot read input" in err


def test_missing_rules_file_returns_2(tmp_path, capsys):
    log = write_log(tmp_path, NORMAL_LOG)
    code = main(["--rules", str(tmp_path / "nope.yaml"), "--auth-log", log])
    out, err = capsys.readouterr()
    assert code == 2
    assert "cannot load rules" in err


def test_invalid_rules_file_returns_2(tmp_path, capsys):
    text = """
rules:
  - id: R001
    name: Broken
    type: signature
    severity: gigantic
    event_type: port_open
"""
    rules = write_text(tmp_path, "rules.yaml", text)
    code = main(["--rules", rules, "--auth-log", write_log(tmp_path, NORMAL_LOG)])
    out, err = capsys.readouterr()
    assert code == 2
    assert "cannot load rules" in err
    assert "rule #1" in err
    assert out == ""


def test_no_inputs_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as info:
        main([])
    assert info.value.code == 2
    assert "provide at least one input" in capsys.readouterr().err


def test_custom_rules_file_is_used(tmp_path, capsys):
    text = """
rules:
  - id: R001
    name: SMB exposed
    type: signature
    severity: high
    event_type: port_open
    dest_ports: [445]
  - id: R002
    name: MSRPC exposed
    type: signature
    severity: low
    event_type: port_open
    dest_ports: [135]
    enabled: false
"""
    rules = write_text(tmp_path, "rules.yaml", text)
    code = main(["--rules", rules, "--scan", write_scan(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Events ingested: 2" in out
    assert "Rules loaded: 2 (1 enabled)" in out
    assert "Alerts: 1 (high: 1)" in out
    assert "[HIGH] R001 SMB exposed" in out
    assert "R002" not in out


def test_format_alert_with_mitre():
    expected = "\n".join(
        [
            "[HIGH] R001 Brute force (T1110.001)",
            "  Time: 2026-06-26 13:01:25 UTC",
            "  5 failed logins",
            "  Evidence: 2 event(s)",
        ]
    )
    assert format_alert(make_alert()) == expected


def test_format_alert_without_mitre():
    expected = "\n".join(
        [
            "[HIGH] R001 Brute force",
            "  Time: 2026-06-26 13:01:25 UTC",
            "  5 failed logins",
            "  Evidence: 2 event(s)",
        ]
    )
    assert format_alert(make_alert(mitre_technique=None)) == expected


def test_format_alert_converts_the_time_to_utc():
    argentina = timezone(timedelta(hours=-3))
    alert = make_alert(timestamp=datetime(2026, 6, 26, 10, 1, 25, tzinfo=argentina))
    assert "  Time: 2026-06-26 13:01:25 UTC" in format_alert(alert)


def test_severity_breakdown_orders_from_most_severe():
    alerts = [
        make_alert("medium"),
        make_alert("high"),
        make_alert("high"),
        make_alert("low"),
        make_alert("critical"),
    ]
    assert severity_breakdown(alerts) == "critical: 1, high: 2, medium: 1, low: 1"