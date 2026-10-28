from datetime import datetime, timedelta, timezone

import pytest

from adapters.login_detector_adapter import parse_auth_log
from engine.event import Event, AUTH_FAILURE, AUTH_SUCCESS, PORT_OPEN
from engine.evaluator import evaluate_sequence
from engine.rule import Rule, SequenceStep

BASE_TIME = datetime(2026, 6, 26, 10, 0, 0, tzinfo=timezone.utc)
IP_A = "185.23.44.10"
IP_B = "10.0.0.50"


def make_event(seconds, **overrides):
    base = dict(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source="login_failure_detector",
        event_type=AUTH_FAILURE,
        src_ip=IP_A,
        user="admin",
    )
    base.update(overrides)
    return Event(**base)


def make_rule(**overrides):
    base = dict(
        rule_id="R003",
        name="Successful brute force",
        rule_type="sequence",
        severity="high",
        mitre_technique="T1110",
        group_by="src_ip",
        window_seconds=300,
        steps=(SequenceStep(AUTH_FAILURE, 5), SequenceStep(AUTH_SUCCESS)),
    )
    base.update(overrides)
    return Rule(**base)


def two_step_rule(**overrides):
    steps = (SequenceStep(AUTH_FAILURE), SequenceStep(AUTH_SUCCESS))
    return make_rule(steps=steps, **overrides)


def attack(offset=0, **overrides):
    events = [make_event(offset + seconds, **overrides) for seconds in (0, 2, 4, 6, 8)]
    events.append(make_event(offset + 10, event_type=AUTH_SUCCESS, **overrides))
    return events


def test_failures_followed_by_a_success_create_one_alert():
    alerts = evaluate_sequence(make_rule(), attack())
    assert len(alerts) == 1


def test_alert_takes_rule_data_and_the_completing_event():
    events = attack()
    alert = evaluate_sequence(make_rule(), events)[0]
    assert alert.rule_id == "R003"
    assert alert.severity == "high"
    assert alert.mitre_technique == "T1110"
    assert alert.timestamp == events[-1].timestamp
    assert alert.event_ids == tuple(event.event_id for event in events)


def test_description_describes_the_sequence():
    alert = evaluate_sequence(make_rule(), attack())[0]
    assert alert.description == (
        "Successful brute force: src_ip=185.23.44.10, "
        "sequence auth_failure x5 -> auth_success within 300s"
    )


def test_description_from_the_rule_is_used():
    rule = make_rule(description="Possible account compromise")
    alert = evaluate_sequence(rule, attack())[0]
    assert alert.description.startswith("Possible account compromise: src_ip=")


def test_steps_without_count_expect_a_single_event():
    events = [make_event(0), make_event(5, event_type=AUTH_SUCCESS)]
    alerts = evaluate_sequence(two_step_rule(), events)
    assert len(alerts) == 1
    assert alerts[0].description == (
        "Successful brute force: src_ip=185.23.44.10, "
        "sequence auth_failure -> auth_success within 300s"
    )


def test_success_before_the_failures_does_not_alert():
    events = [make_event(0, event_type=AUTH_SUCCESS)]
    events += [make_event(seconds) for seconds in (2, 4, 6, 8, 10)]
    assert evaluate_sequence(make_rule(), events) == []


def test_four_failures_are_not_enough():
    events = [make_event(seconds) for seconds in (0, 2, 4, 6)]
    events.append(make_event(8, event_type=AUTH_SUCCESS))
    assert evaluate_sequence(make_rule(), events) == []


def test_failures_without_a_success_do_not_alert():
    events = [make_event(seconds) for seconds in (0, 2, 4, 6, 8, 10)]
    assert evaluate_sequence(make_rule(), events) == []


@pytest.mark.parametrize(
    "gap, expected",
    [(300, 1), (301, 0)],
    ids=["exactly-at-the-edge", "one-second-outside"],
)
def test_window_edge_is_inclusive(gap, expected):
    events = [make_event(0), make_event(gap, event_type=AUTH_SUCCESS)]
    alerts = evaluate_sequence(two_step_rule(), events)
    assert len(alerts) == expected


def test_failures_spread_beyond_the_window_do_not_complete_the_sequence():
    events = [make_event(seconds) for seconds in (0, 100, 200, 300, 400)]
    events.append(make_event(410, event_type=AUTH_SUCCESS))
    assert evaluate_sequence(make_rule(), events) == []


def test_a_success_in_the_middle_does_not_reset_the_sequence():
    events = [make_event(seconds) for seconds in (0, 2, 4, 6, 8)]
    events.append(make_event(3, event_type=AUTH_SUCCESS))
    events.append(make_event(10, event_type=AUTH_SUCCESS))
    alerts = evaluate_sequence(make_rule(), events)
    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 7


def test_unrelated_event_types_are_ignored_and_not_part_of_the_evidence():
    events = attack()
    port_event = make_event(5, event_type=PORT_OPEN, dest_port=22)
    alerts = evaluate_sequence(make_rule(), events + [port_event])
    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 6
    assert port_event.event_id not in alerts[0].event_ids


def test_a_second_success_after_the_alert_does_not_alert_again():
    events = attack() + [make_event(12, event_type=AUTH_SUCCESS)]
    alerts = evaluate_sequence(make_rule(), events)
    assert len(alerts) == 1


def test_two_full_attacks_create_two_alerts():
    events = attack() + attack(offset=1000)
    alerts = evaluate_sequence(make_rule(), events)
    assert len(alerts) == 2
    assert set(alerts[0].event_ids).isdisjoint(alerts[1].event_ids)


def test_events_from_other_ips_do_not_interfere():
    noise = [make_event(seconds, src_ip=IP_B) for seconds in (1, 3, 5)]
    alerts = evaluate_sequence(make_rule(), attack() + noise)
    assert len(alerts) == 1
    assert IP_A in alerts[0].description
    assert IP_B not in alerts[0].description


def test_each_ip_gets_its_own_alert():
    events = attack() + attack(offset=1, src_ip=IP_B)
    alerts = evaluate_sequence(make_rule(), events)
    assert len(alerts) == 2
    assert IP_A in alerts[0].description
    assert IP_B in alerts[1].description
    assert set(alerts[0].event_ids).isdisjoint(alerts[1].event_ids)


def test_events_without_the_group_field_are_ignored():
    assert evaluate_sequence(make_rule(), attack(src_ip=None)) == []


def test_unordered_input_gives_the_same_result():
    events = attack()
    alerts = evaluate_sequence(make_rule(), list(reversed(events)))
    assert len(alerts) == 1
    assert alerts[0].timestamp == events[-1].timestamp


def test_empty_event_list_returns_no_alerts():
    assert evaluate_sequence(make_rule(), []) == []


def test_non_sequence_rule_is_rejected():
    signature_rule = Rule(
        rule_id="R001",
        name="Sensitive port open",
        rule_type="signature",
        severity="high",
        event_type=PORT_OPEN,
    )
    with pytest.raises(ValueError, match="not a sequence rule"):
        evaluate_sequence(signature_rule, attack())


REAL_LOG = [
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


def test_real_log_has_attacks_but_no_successful_brute_force():
    events, rejected = parse_auth_log(REAL_LOG)
    assert rejected == []
    assert evaluate_sequence(make_rule(), events) == []


def test_real_log_with_a_login_after_the_failures_is_flagged():
    lines = REAL_LOG + ["2026-06-26 10:02:00 | SUCCESS_LOGIN | admin | 185.23.44.10"]
    events, rejected = parse_auth_log(lines)
    alerts = evaluate_sequence(make_rule(), events)
    assert rejected == []
    assert len(alerts) == 1
    assert "185.23.44.10" in alerts[0].description
    assert len(alerts[0].event_ids) == 6