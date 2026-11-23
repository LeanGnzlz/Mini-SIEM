from datetime import datetime, timedelta, timezone

import pytest

from adapters.login_detector_adapter import parse_auth_log
from engine.evaluator import (
    describe_group,
    evaluate_sequence,
    evaluate_threshold,
    group_key,
    has_group,
    run_rules,
)
from engine.event import AUTH_FAILURE, AUTH_SUCCESS, Event
from engine.rule import Rule, build_rule, load_rules

BASE_TIME = datetime(2026, 6, 26, 10, 0, 0, tzinfo=timezone.utc)
IP_A = "185.23.44.10"
IP_B = "10.0.0.50"

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

YAML_BOTH_STYLES = """
rules:
  - id: R001
    name: Flow style
    type: threshold
    severity: low
    event_type: auth_failure
    group_by: [src_ip, user]
    window_seconds: 60
    threshold: 3
  - id: R002
    name: Block style
    type: threshold
    severity: low
    event_type: auth_failure
    group_by:
      - src_ip
      - user
    window_seconds: 60
    threshold: 3
"""

YAML_MAPPING = """
rules:
  - id: R001
    name: Broken
    type: threshold
    severity: low
    event_type: auth_failure
    group_by: {src_ip: 1}
    window_seconds: 60
    threshold: 3
"""


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


def failures(seconds, **overrides):
    return [make_event(second, **overrides) for second in seconds]


def threshold_entry(**overrides):
    entry = {
        "id": "B1",
        "name": "Brute force per account",
        "type": "threshold",
        "severity": "medium",
        "event_type": "auth_failure",
        "group_by": ["src_ip", "user"],
        "window_seconds": 300,
        "threshold": 5,
    }
    entry.update(overrides)
    return entry


def sequence_entry(**overrides):
    entry = {
        "id": "S2",
        "name": "Successful brute force",
        "type": "sequence",
        "severity": "high",
        "group_by": ["src_ip", "user"],
        "window_seconds": 300,
        "steps": [
            {"event_type": "auth_failure", "count": 5},
            {"event_type": "auth_success"},
        ],
    }
    entry.update(overrides)
    return entry


def write_rules(tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_group_by_accepts_a_single_field():
    rule = build_rule(threshold_entry(group_by="src_ip"))
    assert rule.group_by == "src_ip"
    assert rule.group_fields == ("src_ip",)


def test_group_by_accepts_a_list_of_fields():
    rule = build_rule(threshold_entry(group_by=["src_ip", "user"]))
    assert rule.group_fields == ("src_ip", "user")


def test_a_list_is_stored_as_a_tuple():
    rule = build_rule(threshold_entry(group_by=["src_ip", "user"]))
    assert isinstance(rule.group_by, tuple)
    assert rule.group_by == ("src_ip", "user")


def test_a_list_with_one_field_is_the_same_as_a_single_field():
    rule = build_rule(threshold_entry(group_by=["src_ip"]))
    assert rule.group_fields == ("src_ip",)


def test_sequence_rules_accept_a_list_of_fields():
    rule = build_rule(sequence_entry(group_by=["src_ip", "user"]))
    assert rule.group_fields == ("src_ip", "user")


def test_a_signature_rule_has_no_group_fields():
    rule = build_rule(
        {
            "id": "R001",
            "name": "Sensitive port open",
            "type": "signature",
            "severity": "high",
            "event_type": "port_open",
        }
    )
    assert rule.group_fields == ()


@pytest.mark.parametrize(
    "value, message",
    [
        ([], "non-empty list"),
        (["src_ip", "src_ip"], "must not repeat"),
        (["src_ip", "color"], "must only use"),
        (["src_ip", 5], "must only use"),
        ("color", "must only use"),
        (5, "non-empty list"),
        ("", "must only use"),
    ],
    ids=[
        "empty-list",
        "repeated-field",
        "unknown-field",
        "number-in-list",
        "unknown-name",
        "number",
        "empty-text",
    ],
)
def test_invalid_group_by_is_rejected(value, message):
    with pytest.raises(ValueError, match=message):
        build_rule(threshold_entry(group_by=value))


def test_a_rule_built_by_hand_rejects_a_list():
    with pytest.raises(ValueError, match="group_by must"):
        Rule(
            rule_id="B1",
            name="n",
            rule_type="threshold",
            severity="low",
            event_type="auth_failure",
            group_by=["src_ip", "user"],
            window_seconds=60,
            threshold=3,
        )


def test_a_rule_built_by_hand_accepts_a_tuple():
    rule = Rule(
        rule_id="B1",
        name="n",
        rule_type="threshold",
        severity="low",
        event_type="auth_failure",
        group_by=("src_ip", "user"),
        window_seconds=60,
        threshold=3,
    )
    assert rule.group_fields == ("src_ip", "user")


def test_distinct_cannot_be_one_of_the_group_fields():
    entry = threshold_entry(group_by=["src_ip", "user"], distinct="user")
    with pytest.raises(ValueError, match="must differ"):
        build_rule(entry)


def test_distinct_can_be_a_field_outside_the_group():
    entry = threshold_entry(group_by=["src_ip", "dest_ip"], distinct="user")
    assert build_rule(entry).distinct == "user"


def test_yaml_accepts_both_list_syntaxes(tmp_path):
    rules = load_rules(write_rules(tmp_path, YAML_BOTH_STYLES))
    assert [rule.group_fields for rule in rules] == [
        ("src_ip", "user"),
        ("src_ip", "user"),
    ]


def test_yaml_mapping_as_group_by_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="rule #1"):
        load_rules(write_rules(tmp_path, YAML_MAPPING))


def test_describe_group_with_one_field():
    assert describe_group(("src_ip",), (IP_A,)) == "src_ip=185.23.44.10"


def test_describe_group_with_two_fields():
    text = describe_group(("src_ip", "user"), (IP_A, "admin"))
    assert text == "src_ip=185.23.44.10, user=admin"


def test_group_key_collects_every_field():
    assert group_key(make_event(0), ("src_ip", "user")) == (IP_A, "admin")


def test_group_key_without_fields_is_empty():
    assert group_key(make_event(0), ()) == ()


def test_has_group_needs_every_field():
    assert has_group(make_event(0), ("src_ip", "user")) is True
    assert has_group(make_event(0, user=None), ("src_ip", "user")) is False


def test_has_group_without_fields_is_always_true():
    assert has_group(make_event(0, src_ip=None, user=None), ()) is True


def test_five_failures_against_one_account_create_one_alert():
    rule = build_rule(threshold_entry())
    assert len(evaluate_threshold(rule, failures((0, 2, 4, 6, 8)))) == 1


def test_five_different_users_from_one_ip_are_not_brute_force():
    users = ["admin", "maria", "juan", "pedro", "carlos"]
    events = [make_event(index * 2, user=user) for index, user in enumerate(users)]
    assert evaluate_threshold(build_rule(threshold_entry()), events) == []


def test_the_description_names_every_group_field():
    alerts = evaluate_threshold(build_rule(threshold_entry()), failures((0, 2, 4, 6, 8)))
    assert alerts[0].description == (
        "Brute force per account: src_ip=185.23.44.10, user=admin, "
        "5 events within 300s"
    )


def test_each_account_is_counted_separately():
    events = failures((0, 2, 4, 6, 8)) + failures((1, 3, 5, 7, 9), user="maria")
    alerts = evaluate_threshold(build_rule(threshold_entry()), events)
    assert len(alerts) == 2
    assert "user=admin" in alerts[0].description
    assert "user=maria" in alerts[1].description
    assert set(alerts[0].event_ids).isdisjoint(alerts[1].event_ids)


def test_failures_spread_over_two_accounts_do_not_add_up():
    events = failures((0, 2, 4)) + failures((1, 3, 5), user="maria")
    assert evaluate_threshold(build_rule(threshold_entry()), events) == []


def test_the_same_user_from_different_ips_is_not_added_together():
    events = failures((0, 2, 4)) + failures((1, 3, 5), src_ip=IP_B)
    assert evaluate_threshold(build_rule(threshold_entry()), events) == []


@pytest.mark.parametrize("field", ["src_ip", "user"])
def test_events_missing_a_group_field_are_ignored(field):
    events = failures((0, 2, 4, 6, 8), **{field: None})
    assert evaluate_threshold(build_rule(threshold_entry()), events) == []


def test_the_order_of_the_group_fields_does_not_change_the_alerts():
    events = failures((0, 2, 4, 6, 8))
    first = evaluate_threshold(
        build_rule(threshold_entry(group_by=["src_ip", "user"])), events
    )
    second = evaluate_threshold(
        build_rule(threshold_entry(group_by=["user", "src_ip"])), events
    )
    assert len(first) == len(second) == 1
    assert first[0].event_ids == second[0].event_ids


def test_a_single_field_keeps_the_original_description():
    rule = build_rule(threshold_entry(group_by="src_ip"))
    alerts = evaluate_threshold(rule, failures((0, 2, 4, 6, 8)))
    assert alerts[0].description == (
        "Brute force per account: src_ip=185.23.44.10, 5 events within 300s"
    )


def test_sequence_grouped_by_ip_and_user_detects_the_compromise():
    events = failures((0, 2, 4, 6, 8)) + [make_event(10, event_type=AUTH_SUCCESS)]
    alerts = evaluate_sequence(build_rule(sequence_entry()), events)
    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 6
    assert alerts[0].description == (
        "Successful brute force: src_ip=185.23.44.10, user=admin, "
        "sequence auth_failure x5 -> auth_success within 300s"
    )


def test_a_success_for_another_account_does_not_complete_the_sequence():
    events = failures((0, 2, 4, 6, 8))
    events.append(make_event(10, event_type=AUTH_SUCCESS, user="maria"))
    assert evaluate_sequence(build_rule(sequence_entry()), events) == []


def test_grouping_by_ip_only_treats_it_as_one_episode():
    events = failures((0, 2, 4, 6, 8))
    events.append(make_event(10, event_type=AUTH_SUCCESS, user="maria"))
    rule = build_rule(sequence_entry(group_by="src_ip"))
    assert len(evaluate_sequence(rule, events)) == 1


def test_real_log_per_account_rule_ignores_the_spraying_ip():
    events, rejected = parse_auth_log(REAL_LOG)
    assert rejected == []
    alerts = evaluate_threshold(build_rule(threshold_entry()), events)
    assert len(alerts) == 1
    assert "src_ip=185.23.44.10, user=admin" in alerts[0].description


def test_real_log_brute_force_and_spraying_no_longer_share_evidence():
    events, rejected = parse_auth_log(REAL_LOG)
    spraying = {
        "id": "S1",
        "name": "Password spraying",
        "type": "threshold",
        "severity": "medium",
        "event_type": "auth_failure",
        "group_by": "src_ip",
        "window_seconds": 300,
        "threshold": 5,
        "distinct": "user",
    }
    rules = [build_rule(threshold_entry()), build_rule(spraying)]
    alerts = run_rules(rules, events)
    assert [alert.rule_id for alert in alerts] == ["B1", "S1"]
    assert set(alerts[0].event_ids).isdisjoint(alerts[1].event_ids)
    assert "10.0.0.50" in alerts[1].description