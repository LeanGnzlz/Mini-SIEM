from datetime import datetime, timezone

import pytest

from adapters.login_detector_adapter import parse_line, parse_auth_log, load_auth_log
from engine.event import AUTH_FAILURE, AUTH_SUCCESS

FAILED_LINE = "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10"
SUCCESS_LINE = "2026-06-26 10:00:01 | SUCCESS_LOGIN | leandro | 192.168.1.20"

SAMPLE_LOG = [
    "2026-06-26 10:00:01 | SUCCESS_LOGIN | leandro | 192.168.1.20",
    "2026-06-26 10:01:15 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:17 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:20 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:22 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:01:25 | FAILED_LOGIN | admin | 185.23.44.10",
    "2026-06-26 10:05:10 | SUCCESS_LOGIN | maria | 192.168.1.30",
    "2026-06-26 11:00:01 | FAILED_LOGIN | admin | 10.0.0.50",
    "2026-06-26 11:00:03 | FAILED_LOGIN | maria | 10.0.0.50",
    "2026-06-26 11:00:05 | FAILED_LOGIN | juan | 10.0.0.50",
    "2026-06-26 11:00:07 | FAILED_LOGIN | pedro | 10.0.0.50",
    "2026-06-26 11:00:09 | FAILED_LOGIN | carlos | 10.0.0.50",
]


def test_failed_login_line_is_mapped():
    event = parse_line(FAILED_LINE)
    assert event.source == "login_failure_detector"
    assert event.event_type == AUTH_FAILURE
    assert event.user == "admin"
    assert event.src_ip == "185.23.44.10"
    assert event.dest_ip is None


def test_success_login_line_is_mapped():
    event = parse_line(SUCCESS_LINE)
    assert event.event_type == AUTH_SUCCESS
    assert event.user == "leandro"
    assert event.src_ip == "192.168.1.20"


def test_timestamp_is_converted_to_utc():
    event = parse_line(FAILED_LINE)
    expected = datetime(2026, 6, 26, 10, 1, 15).astimezone(timezone.utc)
    assert event.timestamp == expected
    assert event.timestamp.utcoffset().total_seconds() == 0


def test_raw_data_keeps_original_line():
    assert parse_line(FAILED_LINE + "\n").raw_data == FAILED_LINE


def test_wrong_field_count_is_rejected():
    with pytest.raises(ValueError):
        parse_line("2026-06-26 10:01:15 | FAILED_LOGIN | admin")


def test_empty_field_is_rejected():
    with pytest.raises(ValueError):
        parse_line("2026-06-26 10:01:15 | FAILED_LOGIN |  | 185.23.44.10")


def test_unknown_event_type_is_rejected():
    with pytest.raises(ValueError):
        parse_line("2026-06-26 10:01:15 | LOGOUT | admin | 185.23.44.10")


def test_invalid_ip_is_rejected():
    with pytest.raises(ValueError):
        parse_line("2026-06-26 10:01:15 | FAILED_LOGIN | admin | 999.1.1.1")


def test_bad_date_is_rejected():
    with pytest.raises(ValueError):
        parse_line("26/06/2026 | FAILED_LOGIN | admin | 185.23.44.10")


def test_blank_lines_are_skipped_silently():
    events, rejected = parse_auth_log(["", "   ", FAILED_LINE])
    assert len(events) == 1
    assert rejected == []


def test_rejected_line_reports_its_number_and_valid_lines_are_kept():
    lines = [SUCCESS_LINE, "this is not a log line", "", FAILED_LINE]
    events, rejected = parse_auth_log(lines)
    assert len(events) == 2
    assert len(rejected) == 1
    assert rejected[0].startswith("line 2")


def test_real_sample_log_parses_without_rejections():
    events, rejected = parse_auth_log(SAMPLE_LOG)
    assert len(events) == 12
    assert rejected == []


def test_load_auth_log_reads_file(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(SAMPLE_LOG), encoding="utf-8")
    events, rejected = load_auth_log(path)
    assert len(events) == 12
    assert rejected == []