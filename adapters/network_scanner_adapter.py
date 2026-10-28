import json
from datetime import datetime, timezone
from pathlib import Path

from engine.event import Event, PORT_OPEN

SOURCE_NAME = "network_scanner"
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def parse_timestamp(text: str) -> datetime:
    naive = datetime.strptime(text, TIMESTAMP_FORMAT)
    return naive.astimezone(timezone.utc)


def parse_scan_report(data: dict) -> list[Event]:
    try:
        target = data["target"]
        timestamp = parse_timestamp(data["completed"])
        open_ports = data["open_ports"]
    except KeyError as error:
        raise ValueError(f"missing field in scan report: {error}") from error

    events = []
    for entry in open_ports:
        try:
            port = entry["port"]
        except KeyError as error:
            raise ValueError(f"missing field in open port entry: {error}") from error
        events.append(
            Event(
                timestamp=timestamp,
                source=SOURCE_NAME,
                event_type=PORT_OPEN,
                dest_ip=target,
                dest_port=port,
                raw_data=json.dumps(entry),
            )
        )
    return events


def load_scan_report(path) -> list[Event]:
    with open(Path(path), encoding="utf-8") as file:
        data = json.load(file)
    return parse_scan_report(data)