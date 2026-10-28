from dataclasses import FrozenInstanceError

import pytest

from engine.rule import SequenceStep, build_rule, load_rules


def signature_entry(**overrides):
    entry = {
        "id": "R001",
        "name": "Sensitive port open",
        "type": "signature",
        "severity": "high",
        "event_type": "port_open",
        "dest_ports": [3389, 445],
    }
    entry.update(overrides)
    return entry


def threshold_entry(**overrides):
    entry = {
        "id": "R002",
        "name": "Brute force",
        "type": "threshold",
        "severity": "medium",
        "mitre": "T1110.001",
        "event_type": "auth_failure",
        "group_by": "src_ip",
        "window_seconds": 300,
        "threshold": 5,
    }
    entry.update(overrides)
    return entry


def sequence_entry(**overrides):
    entry = {
        "id": "R003",
        "name": "Successful brute force",
        "type": "sequence",
        "severity": "high",
        "mitre": "T1110",
        "group_by": "src_ip",
        "window_seconds": 300,
        "steps": [
            {"event_type": "auth_failure", "count": 5},
            {"event_type": "auth_success"},
        ],
    }
    entry.update(overrides)
    return entry


def without(entry, *keys):
    return {key: value for key, value in entry.items() if key not in keys}


def assert_rejected(entry, text):
    with pytest.raises(ValueError, match=text):
        build_rule(entry)


def write_rules(tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_signature_rule():
    rule = build_rule(signature_entry())
    assert rule.rule_type == "signature"
    assert rule.dest_ports == (3389, 445)


def test_valid_threshold_rule():
    rule = build_rule(threshold_entry())
    assert rule.rule_id == "R002"
    assert rule.mitre_technique == "T1110.001"
    assert rule.window_seconds == 300
    assert rule.threshold == 5
    assert rule.enabled is True


def test_valid_sequence_rule():
    rule = build_rule(sequence_entry())
    assert len(rule.steps) == 2
    assert isinstance(rule.steps[0], SequenceStep)
    assert rule.steps[0].count == 5
    assert rule.steps[1].count == 1


def test_threshold_rule_with_distinct_is_valid():
    rule = build_rule(threshold_entry(distinct="user"))
    assert rule.distinct == "user"


def test_signature_rule_without_ports_is_valid():
    rule = build_rule(without(signature_entry(), "dest_ports"))
    assert rule.dest_ports == ()


def test_disabled_rule_is_loaded():
    rule = build_rule(threshold_entry(enabled=False))
    assert rule.enabled is False


def test_rule_is_immutable():
    rule = build_rule(threshold_entry())
    with pytest.raises(FrozenInstanceError):
        rule.severity = "low"


def test_unknown_field_is_rejected():
    assert_rejected(threshold_entry(windows_seconds=300), "unknown field")


@pytest.mark.parametrize("key", ["id", "name", "type", "severity"])
def test_missing_required_field_is_rejected(key):
    assert_rejected(without(threshold_entry(), key), "missing field")


def test_unknown_rule_type_is_rejected():
    assert_rejected(threshold_entry(type="magic"), "unknown rule type")


@pytest.mark.parametrize("severity", ["HIGH", "gigantic", ""])
def test_invalid_severity_is_rejected(severity):
    assert_rejected(threshold_entry(severity=severity), "invalid severity")


@pytest.mark.parametrize("technique", ["1110", "t1110", "T1110.1"])
def test_invalid_mitre_id_is_rejected(technique):
    assert_rejected(threshold_entry(mitre=technique), "invalid MITRE")


def test_enabled_must_be_boolean():
    assert_rejected(threshold_entry(enabled="yes"), "enabled")


@pytest.mark.parametrize(
    "entry",
    [
        signature_entry(threshold=5),
        threshold_entry(dest_ports=[22]),
        sequence_entry(event_type="auth_failure"),
    ],
    ids=["threshold-in-signature", "ports-in-threshold", "event-type-in-sequence"],
)
def test_field_from_another_rule_type_is_rejected(entry):
    assert_rejected(entry, "does not apply")


def test_event_type_typo_is_rejected():
    assert_rejected(threshold_entry(event_type="auth_faliure"), "unknown event type")


@pytest.mark.parametrize(
    "key, text",
    [
        ("event_type", "event type"),
        ("group_by", "group_by"),
        ("window_seconds", "window_seconds"),
        ("threshold", "threshold"),
    ],
)
def test_threshold_rule_requires_its_fields(key, text):
    assert_rejected(without(threshold_entry(), key), text)


@pytest.mark.parametrize("value", [0, -1, True, "5", 2.5])
def test_threshold_must_be_positive_integer(value):
    assert_rejected(threshold_entry(threshold=value), "threshold must")


@pytest.mark.parametrize("value", [0, -5, False, "300"])
def test_window_must_be_positive_integer(value):
    assert_rejected(threshold_entry(window_seconds=value), "window_seconds must")


def test_group_by_must_be_a_known_field():
    assert_rejected(threshold_entry(group_by="dest_port"), "group_by must")


def test_distinct_must_differ_from_group_by():
    assert_rejected(threshold_entry(distinct="src_ip"), "must differ")


def test_distinct_must_be_a_known_field():
    assert_rejected(threshold_entry(distinct="color"), "distinct must be")


@pytest.mark.parametrize("port", [70000, -1, True, "445"])
def test_invalid_destination_port_is_rejected(port):
    assert_rejected(signature_entry(dest_ports=[port]), "invalid port")


def test_dest_ports_must_be_a_list():
    assert_rejected(signature_entry(dest_ports=445), "must be a list")


def test_sequence_needs_at_least_two_steps():
    entry = sequence_entry(steps=[{"event_type": "auth_failure"}])
    assert_rejected(entry, "at least 2")


def test_steps_must_be_a_list():
    assert_rejected(sequence_entry(steps="auth_failure"), "must be a list")


def test_step_with_unknown_field_is_rejected():
    entry = sequence_entry(
        steps=[
            {"event_type": "auth_failure", "cuont": 5},
            {"event_type": "auth_success"},
        ]
    )
    assert_rejected(entry, "unknown field")


def test_step_without_event_type_is_rejected():
    entry = sequence_entry(steps=[{"count": 2}, {"event_type": "auth_success"}])
    assert_rejected(entry, "missing 'event_type'")


def test_step_with_unknown_event_type_is_rejected():
    entry = sequence_entry(steps=[{"event_type": "nope"}, {"event_type": "auth_success"}])
    assert_rejected(entry, "unknown event type in step")


@pytest.mark.parametrize("count", [0, -1, True])
def test_step_count_must_be_positive(count):
    entry = sequence_entry(
        steps=[
            {"event_type": "auth_failure", "count": count},
            {"event_type": "auth_success"},
        ]
    )
    assert_rejected(entry, "step count")


def test_step_must_be_a_mapping():
    entry = sequence_entry(steps=["auth_failure", "auth_success"])
    assert_rejected(entry, "mapping")


@pytest.mark.parametrize("entry", ["hello", ["a"], None])
def test_rule_entry_must_be_a_mapping(entry):
    assert_rejected(entry, "mapping")


VALID_RULES_YAML = """
rules:
  - id: R001
    name: Brute force
    type: threshold
    severity: medium
    mitre: T1110.001
    event_type: auth_failure
    group_by: src_ip
    window_seconds: 300
    threshold: 5
  - id: R002
    name: RDP port exposed
    type: signature
    severity: high
    event_type: port_open
    dest_ports: [3389]
"""


def test_load_rules_reads_valid_file(tmp_path):
    rules = load_rules(write_rules(tmp_path, VALID_RULES_YAML))
    assert [rule.rule_id for rule in rules] == ["R001", "R002"]
    assert rules[1].dest_ports == (3389,)


def test_error_names_the_position_of_the_bad_rule(tmp_path):
    text = """
rules:
  - id: R001
    name: Fine rule
    type: signature
    severity: medium
    event_type: port_open
  - id: R002
    name: Broken rule
    type: signature
    severity: gigantic
    event_type: port_open
"""
    with pytest.raises(ValueError, match="rule #2"):
        load_rules(write_rules(tmp_path, text))


def test_duplicate_rule_ids_are_rejected(tmp_path):
    text = """
rules:
  - id: R001
    name: First
    type: signature
    severity: medium
    event_type: port_open
  - id: R001
    name: Second
    type: signature
    severity: medium
    event_type: port_open
"""
    with pytest.raises(ValueError, match="duplicate"):
        load_rules(write_rules(tmp_path, text))


def test_invalid_yaml_syntax_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="invalid YAML"):
        load_rules(write_rules(tmp_path, "rules: [unclosed"))


@pytest.mark.parametrize(
    "text",
    ["", "other: 1", "rules: 5", "- just\n- a list"],
    ids=["empty", "no-rules-key", "rules-not-a-list", "top-level-list"],
)
def test_wrong_file_structure_is_rejected(tmp_path, text):
    with pytest.raises(ValueError, match="must contain"):
        load_rules(write_rules(tmp_path, text))


def test_missing_file_is_not_hidden(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(tmp_path / "nope.yaml")


def test_yaml_yes_is_not_accepted_as_a_number(tmp_path):
    text = """
rules:
  - id: R001
    name: Brute force
    type: threshold
    severity: medium
    event_type: auth_failure
    group_by: src_ip
    window_seconds: 300
    threshold: yes
"""
    with pytest.raises(ValueError, match="threshold"):
        load_rules(write_rules(tmp_path, text))


def test_unsafe_yaml_tags_are_rejected(tmp_path):
    text = "rules: !!python/object/apply:os.getcwd []"
    with pytest.raises(ValueError, match="invalid YAML"):
        load_rules(write_rules(tmp_path, text))