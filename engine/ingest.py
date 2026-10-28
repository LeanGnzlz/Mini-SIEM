from pathlib import Path

from adapters.login_detector_adapter import load_auth_log
from adapters.network_scanner_adapter import load_scan_report
from engine.event import Event


def ingest(scan_report_paths=(), auth_log_paths=()) -> tuple[list[Event], list[str]]:
    events = []
    rejected = []

    for path in scan_report_paths:
        try:
            events.extend(load_scan_report(path))
        except ValueError as error:
            rejected.append(f"{Path(path).name}: {error}")

    for path in auth_log_paths:
        file_events, file_rejected = load_auth_log(path)
        events.extend(file_events)
        rejected.extend(f"{Path(path).name}: {message}" for message in file_rejected)

    events.sort(key=lambda event: event.timestamp)
    return events, rejected