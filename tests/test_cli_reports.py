import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.report import format_txt_report
from mini_siem import main, utc_now

FIXED_NOW = datetime(2026, 10, 29, 19, 56, 0, tzinfo=timezone.utc)
JSON_NAME = "siem_report_20261029_195600.json"
TXT_NAME = "siem_report_20261029_195600.txt"

SCAN_REPORT = {
    "target": "127.0.0.1",
    "scan_duration": 21.21,
    "completed": "2026-06-25 13:58:39",
    "open_ports": [
        {"port": 135, "service": "MSRPC", "banner": "Not applicable"},
        {"port": 445, "service": "SMB", "banner": "Not applicable"},
    ],
}

VALID_LINE = "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10"

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


def fixed_clock():
    return FIXED_NOW


def counting_clock():
    calls = []

    def clock():
        calls.append(1)
        return FIXED_NOW

    return clock, calls


def write_scan(folder, name="scan.json"):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text(json.dumps(SCAN_REPORT), encoding="utf-8")
    return str(path)


def write_log(folder, lines, name="auth.log"):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def full_inputs(tmp_path):
    folder = tmp_path / "inputs"
    return [
        "--scan",
        write_scan(folder),
        "--auth-log",
        write_log(folder, LOG_WITH_COMPROMISE),
    ]


def run_full(tmp_path, reports=None, now=fixed_clock):
    reports = reports or tmp_path / "reports"
    code = main(full_inputs(tmp_path) + ["--report-dir", str(reports)], now=now)
    assert code == 0
    return reports


def read_json(reports):
    return json.loads((reports / JSON_NAME).read_text(encoding="utf-8"))


def read_txt(reports):
    return (reports / TXT_NAME).read_text(encoding="utf-8")


def test_without_report_dir_nothing_is_written(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    code = main(full_inputs(tmp_path))
    out = capsys.readouterr().out
    assert code == 0
    assert "Report written" not in out
    assert [path.name for path in tmp_path.iterdir()] == ["inputs"]


def test_without_report_dir_the_clock_is_not_read(tmp_path):
    clock, calls = counting_clock()
    assert main(full_inputs(tmp_path), now=clock) == 0
    assert calls == []


def test_report_dir_creates_json_and_txt_with_the_same_name(tmp_path, capsys):
    reports = run_full(tmp_path)
    out, err = capsys.readouterr()
    assert err == ""
    assert sorted(path.name for path in reports.iterdir()) == [JSON_NAME, TXT_NAME]


def test_report_paths_are_printed_after_the_alerts(tmp_path, capsys):
    reports = run_full(tmp_path)
    out = capsys.readouterr().out
    printed = [
        line.split(": ", 1)[1]
        for line in out.splitlines()
        if line.startswith("Report written: ")
    ]
    assert [Path(item).name for item in printed] == [JSON_NAME, TXT_NAME]
    assert all(Path(item).exists() for item in printed)
    assert out.index("Alerts: 5") < out.index("Report written")


def test_report_dir_is_created_when_missing(tmp_path):
    reports = run_full(tmp_path, tmp_path / "nested" / "reports")
    assert reports.is_dir()
    assert len(list(reports.iterdir())) == 2


def test_json_report_matches_the_run(tmp_path):
    data = read_json(run_full(tmp_path))
    assert data["generated_at"] == "2026-10-29T19:56:00+00:00"
    assert data["summary"] == {
        "events_ingested": 15,
        "rejected_inputs": 0,
        "rules_loaded": 4,
        "rules_enabled": 4,
        "alerts": 5,
        "alerts_by_severity": {"high": 2, "medium": 3},
    }
    assert [entry["rule_id"] for entry in data["alerts"]] == [
        "R001",
        "R002",
        "R003",
        "R002",
        "R004",
    ]
    assert all(len(entry["evidence"]) == len(entry["event_ids"]) for entry in data["alerts"])


def test_txt_report_is_built_from_the_same_report(tmp_path):
    reports = run_full(tmp_path)
    assert read_txt(reports) == format_txt_report(read_json(reports))


def test_clock_is_read_once(tmp_path):
    clock, calls = counting_clock()
    run_full(tmp_path, now=clock)
    assert len(calls) == 1


def test_rejected_inputs_reach_the_reports(tmp_path):
    reports = tmp_path / "reports"
    log = write_log(tmp_path / "inputs", [VALID_LINE, "this is not a log line"])
    code = main(["--auth-log", log, "--report-dir", str(reports)], now=fixed_clock)
    assert code == 0
    data = read_json(reports)
    assert data["summary"]["rejected_inputs"] == 1
    assert len(data["rejected"]) == 1
    assert data["rejected"][0].startswith("auth.log: line 2")
    lines = read_txt(reports).splitlines()
    assert any(line.startswith("  - auth.log: line 2") for line in lines)


def test_report_without_alerts_is_still_written(tmp_path):
    reports = tmp_path / "reports"
    log = write_log(tmp_path / "inputs", NORMAL_LOG)
    code = main(["--auth-log", log, "--report-dir", str(reports)], now=fixed_clock)
    assert code == 0
    data = read_json(reports)
    assert data["summary"]["alerts"] == 0
    assert data["alerts"] == []
    assert "  No alerts." in read_txt(reports).splitlines()


def test_existing_report_returns_2_and_keeps_the_original(tmp_path, capsys):
    args = full_inputs(tmp_path) + ["--report-dir", str(tmp_path / "reports")]
    assert main(args, now=fixed_clock) == 0
    capsys.readouterr()
    reports = tmp_path / "reports"
    original = {path.name: path.read_text(encoding="utf-8") for path in reports.iterdir()}
    code = main(args, now=fixed_clock)
    out, err = capsys.readouterr()
    assert code == 2
    assert "cannot write report" in err
    assert "Alerts: 5 (high: 2, medium: 3)" in out
    assert "Report written" not in out
    current = {path.name: path.read_text(encoding="utf-8") for path in reports.iterdir()}
    assert current == original


def test_unusable_report_dir_returns_2(tmp_path, capsys):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a folder", encoding="utf-8")
    args = full_inputs(tmp_path) + ["--report-dir", str(blocker)]
    code = main(args, now=fixed_clock)
    out, err = capsys.readouterr()
    assert code == 2
    assert "cannot write report" in err
    assert "Alerts: 5 (high: 2, medium: 3)" in out
    assert blocker.read_text(encoding="utf-8") == "not a folder"


def test_report_dir_without_a_value_is_a_usage_error(tmp_path, capsys):
    log = write_log(tmp_path / "inputs", NORMAL_LOG)
    with pytest.raises(SystemExit) as info:
        main(["--auth-log", log, "--report-dir"])
    assert info.value.code == 2
    assert "expected one argument" in capsys.readouterr().err


def test_utc_now_is_timezone_aware_utc():
    moment = utc_now()
    assert moment.utcoffset() == timedelta(0)
    assert abs(datetime.now(timezone.utc) - moment) < timedelta(seconds=5)