import json
from datetime import datetime, timezone

import pytest

from adapters.network_scanner_adapter import parse_scan_report, load_scan_report
from engine.event import PORT_OPEN


def sample_report():
    return {
        "target": "127.0.0.1",
        "scan_duration": 21.21,
        "completed": "2026-06-25 13:58:39",
        "open_ports": [
            {"port": 135, "service": "MSRPC", "banner": "Not applicable"},
            {"port": 445, "service": "SMB", "banner": "Not applicable"},
        ],
    }


def test_one_event_is_created_per_open_port():
    events = parse_scan_report(sample_report())
    assert len(events) == 2


def test_event_fields_are_mapped():
    event = parse_scan_report(sample_report())[0]
    assert event.source == "network_scanner"
    assert event.event_type == PORT_OPEN
    assert event.dest_ip == "127.0.0.1"
    assert event.dest_port == 135


def test_timestamp_is_converted_to_utc():
    event = parse_scan_report(sample_report())[0]
    expected = datetime(2026, 6, 25, 13, 58, 39).astimezone(timezone.utc)
    assert event.timestamp == expected
    assert event.timestamp.utcoffset().total_seconds() == 0


def test_raw_data_keeps_service_and_banner():
    event = parse_scan_report(sample_report())[1]
    raw = json.loads(event.raw_data)
    assert raw["service"] == "SMB"
    assert raw["banner"] == "Not applicable"


def test_report_without_open_ports_returns_no_events():
    report = sample_report()
    report["open_ports"] = []
    assert parse_scan_report(report) == []


def test_missing_target_is_rejected():
    report = sample_report()
    del report["target"]
    with pytest.raises(ValueError):
        parse_scan_report(report)


def test_missing_port_in_entry_is_rejected():
    report = sample_report()
    del report["open_ports"][0]["port"]
    with pytest.raises(ValueError):
        parse_scan_report(report)


def test_bad_date_format_is_rejected():
    report = sample_report()
    report["completed"] = "25/06/2026"
    with pytest.raises(ValueError):
        parse_scan_report(report)


def test_invalid_port_is_rejected():
    report = sample_report()
    report["open_ports"][0]["port"] = 70000
    with pytest.raises(ValueError):
        parse_scan_report(report)


def test_load_scan_report_reads_file(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(sample_report()), encoding="utf-8")
    events = load_scan_report(path)
    assert len(events) == 2


def test_broken_json_file_raises_value_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{ esto no es json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_scan_report(path)