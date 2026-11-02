from collections import deque
from datetime import timedelta

from engine.alert import Alert
from engine.event import Event
from engine.identity import assign_stable_alert_ids
from engine.rule import Rule


def evaluate_signature(rule: Rule, events: list[Event]) -> list[Alert]:
    if rule.rule_type != "signature":
        raise ValueError(f"rule {rule.rule_id} is not a signature rule")
    alerts = []
    for event in events:
        if event.event_type != rule.event_type:
            continue
        if rule.dest_ports and event.dest_port not in rule.dest_ports:
            continue
        alerts.append(
            Alert(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                timestamp=event.timestamp,
                description=rule.description or rule.name,
                event_ids=(event.event_id,),
                mitre_technique=rule.mitre_technique,
            )
        )
    return alerts


def measure(window, distinct) -> int:
    if distinct is None:
        return len(window)
    return len({getattr(event, distinct) for event in window})


def evaluate_threshold(rule: Rule, events: list[Event]) -> list[Alert]:
    if rule.rule_type != "threshold":
        raise ValueError(f"rule {rule.rule_id} is not a threshold rule")

    relevant = [
        event
        for event in events
        if event.event_type == rule.event_type
        and getattr(event, rule.group_by) is not None
        and (rule.distinct is None or getattr(event, rule.distinct) is not None)
    ]
    relevant.sort(key=lambda event: event.timestamp)

    groups = {}
    for event in relevant:
        groups.setdefault(getattr(event, rule.group_by), []).append(event)

    unit = "events" if rule.distinct is None else f"distinct {rule.distinct} values"
    base = rule.description or rule.name
    span = timedelta(seconds=rule.window_seconds)
    alerts = []

    for key, group_events in groups.items():
        window = deque()
        active = False
        for event in group_events:
            limit = event.timestamp - span
            while window and window[0].timestamp < limit:
                window.popleft()
            if measure(window, rule.distinct) < rule.threshold:
                active = False
            window.append(event)
            count = measure(window, rule.distinct)
            if count >= rule.threshold and not active:
                active = True
                alerts.append(
                    Alert(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        timestamp=event.timestamp,
                        description=(
                            f"{base}: {rule.group_by}={key}, "
                            f"{count} {unit} within {rule.window_seconds}s"
                        ),
                        event_ids=tuple(item.event_id for item in window),
                        mitre_technique=rule.mitre_technique,
                    )
                )

    alerts.sort(key=lambda alert: alert.timestamp)
    return alerts


def matches_sequence(window, pattern) -> bool:
    position = 0
    for event in window:
        if event.event_type == pattern[position]:
            position += 1
            if position == len(pattern):
                return True
    return False


def describe_steps(steps) -> str:
    parts = [
        f"{step.event_type} x{step.count}" if step.count > 1 else step.event_type
        for step in steps
    ]
    return " -> ".join(parts)


def evaluate_sequence(rule: Rule, events: list[Event]) -> list[Alert]:
    if rule.rule_type != "sequence":
        raise ValueError(f"rule {rule.rule_id} is not a sequence rule")

    pattern = [step.event_type for step in rule.steps for _ in range(step.count)]
    step_types = set(pattern)

    relevant = [
        event
        for event in events
        if event.event_type in step_types and getattr(event, rule.group_by) is not None
    ]
    relevant.sort(key=lambda event: event.timestamp)

    groups = {}
    for event in relevant:
        groups.setdefault(getattr(event, rule.group_by), []).append(event)

    base = rule.description or rule.name
    steps_text = describe_steps(rule.steps)
    span = timedelta(seconds=rule.window_seconds)
    alerts = []

    for key, group_events in groups.items():
        window = deque()
        for event in group_events:
            limit = event.timestamp - span
            while window and window[0].timestamp < limit:
                window.popleft()
            window.append(event)
            if matches_sequence(window, pattern):
                alerts.append(
                    Alert(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        timestamp=event.timestamp,
                        description=(
                            f"{base}: {rule.group_by}={key}, "
                            f"sequence {steps_text} within {rule.window_seconds}s"
                        ),
                        event_ids=tuple(item.event_id for item in window),
                        mitre_technique=rule.mitre_technique,
                    )
                )
                window.clear()

    alerts.sort(key=lambda alert: alert.timestamp)
    return alerts


EVALUATORS = {
    "signature": evaluate_signature,
    "threshold": evaluate_threshold,
    "sequence": evaluate_sequence,
}


def run_rules(rules: list[Rule], events: list[Event]) -> list[Alert]:
    alerts = []
    for rule in rules:
        if not rule.enabled:
            continue
        alerts.extend(EVALUATORS[rule.rule_type](rule, events))
    alerts.sort(key=lambda alert: alert.timestamp)
    return assign_stable_alert_ids(alerts)