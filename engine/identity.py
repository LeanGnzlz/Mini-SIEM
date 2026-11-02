import hashlib
import json
from collections import Counter
from dataclasses import replace
from datetime import timezone

from engine.event import Event


def content_text(event: Event) -> str:
    fields = [
        event.timestamp.astimezone(timezone.utc).isoformat(),
        event.source,
        event.event_type,
        event.src_ip,
        event.dest_ip,
        event.dest_port,
        event.user,
        event.severity_raw,
        event.raw_data,
    ]
    return json.dumps(fields, ensure_ascii=False)


def stable_event_id(content: str, occurrence: int) -> str:
    text = f"{content}#{occurrence}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def assign_stable_ids(events: list[Event]) -> list[Event]:
    seen = Counter()
    result = []
    for event in events:
        content = content_text(event)
        seen[content] += 1
        result.append(replace(event, event_id=stable_event_id(content, seen[content])))
    return result