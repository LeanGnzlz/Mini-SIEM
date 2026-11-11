from pathlib import Path

from adapters.login_detector_adapter import load_auth_log
from adapters.network_scanner_adapter import load_scan_report
from engine.event import Event
from engine.identity import assign_stable_ids


def ingest(scan_report_paths=(), auth_log_paths=()) -> tuple[list[Event], list[str]]:
    events = []
    rejected = []
    seen_ids = set()

    def add_file_events(name, file_events):
        duplicates = 0
        for event in assign_stable_ids(file_events):
            if event.event_id in seen_ids:
                duplicates += 1
                continue
            seen_ids.add(event.event_id)
            events.append(event)
        if duplicates:
            rejected.append(
                f"{name}: {duplicates} duplicate event(s) skipped, "
                "already ingested from another file"
            )

    for path in scan_report_paths:
        name = Path(path).name
        try:
            file_events = load_scan_report(path)
        except ValueError as error:
            rejected.append(f"{name}: {error}")
            continue
        add_file_events(name, file_events)

    for path in auth_log_paths:
        name = Path(path).name
        file_events, file_rejected = load_auth_log(path)
        rejected.extend(f"{name}: {message}" for message in file_rejected)
        add_file_events(name, file_events)

    events.sort(key=lambda event: event.timestamp)
    return events, rejected


def merge_events(history: list[Event], new_events: list[Event]) -> list[Event]:
    merged = []
    seen_ids = set()
    for event in history + new_events:
        if event.event_id in seen_ids:
            continue
        seen_ids.add(event.event_id)
        merged.append(event)
    merged.sort(key=lambda event: event.timestamp)
    return merged