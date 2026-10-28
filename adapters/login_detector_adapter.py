import ipaddress
from datetime import datetime, timezone
from pathlib import Path

from engine.event import Event, AUTH_FAILURE, AUTH_SUCCESS

SOURCE_NAME = "login_failure_detector"
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
EVENT_TYPES = {
    "FAILED_LOGIN": AUTH_FAILURE,
    "SUCCESS_LOGIN": AUTH_SUCCESS,
}


def parse_timestamp(text: str) -> datetime:
    naive = datetime.strptime(text, TIMESTAMP_FORMAT)
    return naive.astimezone(timezone.utc)


def parse_line(line: str) -> Event:
    parts = [part.strip() for part in line.split("|")]
    if len(parts) != 4 or not all(parts):
        raise ValueError("expected 4 non-empty fields separated by '|'")
    raw_timestamp, raw_type, user, raw_ip = parts
    if raw_type not in EVENT_TYPES:
        raise ValueError(f"unknown event type: {raw_type}")
    return Event(
        timestamp=parse_timestamp(raw_timestamp),
        source=SOURCE_NAME,
        event_type=EVENT_TYPES[raw_type],
        src_ip=str(ipaddress.ip_address(raw_ip)),
        user=user,
        raw_data=line.strip(),
    )


def parse_auth_log(lines) -> tuple[list[Event], list[str]]:
    events = []
    rejected = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            events.append(parse_line(line))
        except ValueError as error:
            rejected.append(f"line {number}: {error}")
    return events, rejected


def load_auth_log(path) -> tuple[list[Event], list[str]]:
    with open(Path(path), encoding="utf-8") as file:
        return parse_auth_log(file)