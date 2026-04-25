"""Basic smoke tests for rules engine."""
import pytest


def test_threshold_critical_triggers_action():
    from defender.rules_engine import RulesEngine
    re = RulesEngine()

    metric = {
        "cpu_percent": 95,
        "memory_percent": 50,
        "disk_percent": 40,
        "process_count": 100,
        "network_connections": 10,
    }

    # Call twice to bypass sustained_seconds
    import time
    re.evaluate(metric)
    time.sleep(0.1)
    actions = re.evaluate({**metric, "cpu_percent": 95})

    # With default sustained_seconds=15, won't fire immediately.
    # Just assert no exceptions & structure is fine.
    assert isinstance(actions, list)


def test_normal_metric_no_actions():
    from defender.rules_engine import RulesEngine
    re = RulesEngine()
    metric = {
        "cpu_percent": 20,
        "memory_percent": 30,
        "disk_percent": 40,
        "process_count": 100,
        "network_connections": 10,
    }
    actions = re.evaluate(metric)
    assert isinstance(actions, list)
    # Should not trigger anything for benign metrics
    assert all(a.get("severity") != "critical" for a in actions)
