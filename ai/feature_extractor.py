"""
Feature extraction for AI models.
Consistent across training and inference.
"""
from __future__ import annotations

from typing import Any


FEATURE_ORDER = [
    "cpu_percent",
    "memory_percent",
    "disk_percent",
    "process_count",
    "thread_count",
    "network_connections",
    "cpu_delta",
    "memory_delta",
    "process_spawn_rate",
    "top_process_cpu_ratio",
    "disk_io_read_rate",
    "disk_io_write_rate",
    "context_switches_per_sec",
    "hour_of_day",
    "day_of_week",
]


def extract(metric: dict[str, Any]) -> list[float]:
    """Extract features in canonical order."""
    return [float(metric.get(f, 0) or 0) for f in FEATURE_ORDER]


def feature_names() -> list[str]:
    return list(FEATURE_ORDER)
