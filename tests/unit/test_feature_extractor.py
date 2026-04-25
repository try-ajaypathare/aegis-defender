"""Feature extractor tests."""


def test_extract_order_consistent():
    from ai.feature_extractor import extract, feature_names

    metric = {
        "cpu_percent": 50, "memory_percent": 60, "disk_percent": 40,
        "process_count": 100, "thread_count": 500,
        "network_connections": 10, "cpu_delta": 5, "memory_delta": 2,
        "process_spawn_rate": 1, "top_process_cpu_ratio": 0.3,
        "disk_io_read_rate": 1.5, "disk_io_write_rate": 0.5,
        "context_switches_per_sec": 100, "hour_of_day": 14, "day_of_week": 2,
    }

    features = extract(metric)
    names = feature_names()
    assert len(features) == len(names) == 15


def test_extract_missing_fields_default_zero():
    from ai.feature_extractor import extract
    features = extract({"cpu_percent": 30})
    assert features[0] == 30.0
    assert all(f == 0.0 for f in features[1:])
