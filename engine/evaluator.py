from engine.alert import Alert
from engine.event import Event
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