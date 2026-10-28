from datetime import datetime, timedelta, timezone

import pytest

from adapters.login_detector_adapter import parse_auth_log
from engine.event import Event, AUTH_FAILURE, AUTH_SUCCESS, PORT_OPEN
from engine.evaluator import evaluate_threshold
from engine.rule import Rule

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
        rule_id="R002",
        name="Brute force",
        rule_type="threshold",
        severity="medium",
        mitre_technique="T1110.001",
        event_type=AUTH_FAILURE,
        group_by="src_ip",
        window_seconds=300,
        threshold=5,
    )
    base.update(overrides)
    return Rule(**base)


def make_spraying_rule(**overrides):
    base = dict(
        rule_id="R004",
        name="Password spraying",
        mitre_technique="T1110.003",
        distinct="user",
    )
    base.update(overrides)
    return make_rule(**base)


def five_failures():
    return [make_event(seconds) for seconds in (0, 2, 4, 6, 8)]


def test_five_failures_inside_the_window_create_one_alert():
    alerts = evaluate_threshold(make_rule(), five_failures())
    assert len(alerts) == 1


def test_four_failures_are_not_enough():
    assert evaluate_threshold(make_rule(), five_failures()[:4]) == []


def test_alert_takes_rule_data_and_the_crossing_event():
    events = five_failures()
    alert = evaluate_threshold(make_rule(), events)[0]
    assert alert.rule_id == "R002"
    assert alert.severity == "medium"
    assert alert.mitre_technique == "T1110.001"
    assert alert.timestamp == events[4].timestamp
    assert alert.event_ids == tuple(event.event_id for event in events)


def test_description_describes_the_episode():
    alert = evaluate_threshold(make_rule(), five_failures())[0]
    assert alert.description == "Brute force: src_ip=185.23.44.10, 5 events within 300s"


def test_description_from_the_rule_is_used():
    rule = make_rule(description="Possible brute force")
    alert = evaluate_threshold(rule, five_failures())[0]
    assert alert.description.startswith("Possible brute force: src_ip=")


@pytest.mark.parametrize(
    "gap, expected",
    [(300, 1), (301, 0)],
    ids=["exactly-at-the-edge", "one-second-outside"],
)
def test_window_edge_is_inclusive(gap, expected):
    events = [make_event(0), make_event(gap)]
    alerts = evaluate_threshold(make_rule(threshold=2), events)
    assert len(alerts) == expected


def test_slow_failures_spread_over_time_do_not_alert():
    events = [make_event(seconds) for seconds in (0, 100, 200, 300, 400)]
    assert evaluate_threshold(make_rule(), events) == []


def test_sustained_attack_creates_a_single_alert():
    events = [make_event(index * 2) for index in range(12)]
    alerts = evaluate_threshold(make_rule(), events)
    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 5
    assert alerts[0].timestamp == events[4].timestamp


def test_two_bursts_separated_by_a_pause_create_two_alerts():
    first = [make_event(seconds) for seconds in (0, 2, 4, 6, 8)]
    second = [make_event(seconds) for seconds in (1000, 1002, 1004, 1006, 1008)]
    alerts = evaluate_threshold(make_rule(), first + second)
    assert len(alerts) == 2
    assert set(alerts[0].event_ids).isdisjoint(alerts[1].event_ids)


def test_failures_from_different_ips_are_not_added_together():
    from_a = [make_event(seconds) for seconds in (0, 2, 4)]
    from_b = [make_event(seconds, src_ip=IP_B) for seconds in (1, 3, 5)]
    assert evaluate_threshold(make_rule(), from_a + from_b) == []


def test_each_ip_gets_its_own_alert():
    from_a = [make_event(seconds) for seconds in (0, 2, 4, 6, 8)]
    from_b = [make_event(seconds, src_ip=IP_B) for seconds in (1, 3, 5, 7, 9)]
    alerts = evaluate_threshold(make_rule(), from_a + from_b)
    assert len(alerts) == 2
    assert IP_A in alerts[0].description
    assert IP_B in alerts[1].description
    assert set(alerts[0].event_ids).isdisjoint(alerts[1].event_ids)


def test_other_event_types_do_not_count():
    events = [make_event(seconds) for seconds in (0, 2, 4, 6)]
    events.append(make_event(8, event_type=AUTH_SUCCESS))
    assert evaluate_threshold(make_rule(), events) == []


def test_events_without_the_group_field_are_ignored():
    events = [make_event(seconds, src_ip=None) for seconds in (0, 2, 4, 6, 8)]
    assert evaluate_threshold(make_rule(), events) == []


def test_unordered_input_gives_the_same_result():
    events = five_failures()
    alerts = evaluate_threshold(make_rule(), list(reversed(events)))
    assert len(alerts) == 1
    assert alerts[0].timestamp == events[4].timestamp


def test_empty_event_list_returns_no_alerts():
    assert evaluate_threshold(make_rule(), []) == []


def test_non_threshold_rule_is_rejected():
    signature_rule = Rule(
        rule_id="R001",
        name="Sensitive port open",
        rule_type="signature",
        severity="high",
        event_type=PORT_OPEN,
    )
    with pytest.raises(ValueError, match="not a threshold rule"):
        evaluate_threshold(signature_rule, five_failures())


def test_five_distinct_users_from_one_ip_create_one_alert():
    users = ["admin", "maria", "juan", "pedro", "carlos"]
    events = [make_event(index * 2, user=user) for index, user in enumerate(users)]
    alerts = evaluate_threshold(make_spraying_rule(), events)
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1110.003"
    assert alerts[0].description == (
        "Password spraying: src_ip=185.23.44.10, 5 distinct user values within 300s"
    )


def test_repeated_users_do_not_inflate_the_distinct_count():
    users = ["admin", "maria", "juan", "pedro", "admin"]
    events = [make_event(index * 2, user=user) for index, user in enumerate(users)]
    assert evaluate_threshold(make_spraying_rule(), events) == []


def test_distinct_count_reaches_the_threshold_after_repeats():
    users = ["admin", "maria", "admin", "juan", "pedro", "carlos"]
    events = [make_event(index * 2, user=user) for index, user in enumerate(users)]
    alerts = evaluate_threshold(make_spraying_rule(), events)
    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 6
    assert alerts[0].timestamp == events[5].timestamp
    assert "5 distinct user values" in alerts[0].description


def test_events_without_the_distinct_field_are_ignored():
    events = [make_event(seconds, user=None) for seconds in (0, 2, 4, 6, 8)]
    assert evaluate_threshold(make_spraying_rule(), events) == []


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


def test_real_log_ip_only_brute_force_rule_also_flags_the_spraying_ip():
    events, rejected = parse_auth_log(REAL_LOG)
    alerts = evaluate_threshold(make_rule(), events)
    assert rejected == []
    assert len(alerts) == 2
    assert "185.23.44.10" in alerts[0].description
    assert "10.0.0.50" in alerts[1].description
    assert all(len(alert.event_ids) == 5 for alert in alerts)


def test_real_log_spraying_rule_flags_only_the_spraying_ip():
    events, rejected = parse_auth_log(REAL_LOG)
    alerts = evaluate_threshold(make_spraying_rule(), events)
    assert len(alerts) == 1
    assert "10.0.0.50" in alerts[0].description