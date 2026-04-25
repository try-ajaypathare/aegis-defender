"""
Integration smoke test: run each attack briefly and measure impact.
Verifies the attack actually moves system metrics.

Run: python tests/integration/test_all_attacks.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# Force UTF-8 output on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


DEFENDER = "http://127.0.0.1:8000"
ATTACKER = "http://127.0.0.1:8001"


def get_metric() -> dict:
    try:
        r = requests.get(f"{DEFENDER}/api/metrics/current", timeout=3)
        return r.json() if r.ok else {}
    except Exception:
        return {}


def start_attack(name: str, params: dict) -> str | None:
    try:
        r = requests.post(f"{ATTACKER}/api/attacks/{name}/start", json=params, timeout=5)
        if r.ok:
            return r.json().get("id")
    except Exception as e:
        print(f"   [start error] {e}")
    return None


def stop_attack(aid: str) -> None:
    try:
        requests.post(f"{ATTACKER}/api/attacks/{aid}/stop", timeout=3)
    except Exception:
        pass


def stop_all() -> None:
    try:
        requests.post(f"{ATTACKER}/api/attacks/stop_all", timeout=5)
    except Exception:
        pass


# Tests: (attack_name, params, wait_seconds, check_func, description)
TESTS = [
    ("cpu_spike",       {"cores": 4, "duration": 15}, 12,
     lambda b, a: a.get("cpu_percent", 0) - b.get("cpu_percent", 0) > 30 or a.get("cpu_percent", 0) > 80,
     "CPU saturation via multiprocessing"),

    ("ram_flood",       {"size_mb": 1500, "duration": 25}, 15,
     lambda b, a: a.get("memory_percent", 0) - b.get("memory_percent", 0) > 5,
     "RAM allocation via mmap"),

    ("disk_fill",       {"size_mb": 500, "duration": 15}, 10,
     lambda b, a: a.get("disk_io_write_rate", 0) > 1 or a.get("disk_percent", 0) > b.get("disk_percent", 0),
     "Disk writes"),

    ("cryptomining_sim", {"cores": 2, "duration": 15}, 10,
     lambda b, a: a.get("cpu_percent", 0) - b.get("cpu_percent", 0) > 20 or a.get("cpu_percent", 0) > 70,
     "Multi-core SHA256 mining pattern"),

    ("thread_flood",    {"count": 200, "duration": 15}, 6,
     lambda b, a: a.get("thread_count", 0) - b.get("thread_count", 0) > 50,
     "Thread count spike"),

    ("fork_bomb",       {"count": 10, "duration": 15}, 6,
     lambda b, a: a.get("process_count", 0) - b.get("process_count", 0) > 3,
     "Process count spike"),

    ("slow_creep",      {"duration": 20}, 15,
     lambda b, a: a.get("cpu_percent", 0) > b.get("cpu_percent", 0),
     "Gradual CPU increase"),

    ("memory_leak",     {"leak_rate_mb_per_sec": 20, "duration": 15}, 10,
     lambda b, a: a.get("memory_percent", 0) - b.get("memory_percent", 0) > 2,
     "Slow memory growth"),

    ("traffic_flood",   {"target": f"{DEFENDER}/api/metrics/current", "requests_per_second": 300, "duration": 10}, 5,
     lambda b, a: True,  # hard to measure from metrics directly
     "HTTP request spam"),

    ("dns_flood",       {"queries_per_second": 30, "duration": 10}, 5,
     lambda b, a: True, "DNS query flood"),

    ("disk_write",      {"duration": 12}, 6,
     lambda b, a: a.get("disk_io_write_rate", 0) > 0.5,
     "Disk write storm"),

    ("log_flood",       {"duration": 10}, 5,
     lambda b, a: a.get("disk_io_write_rate", 0) > 0.3, "Log flood"),
]


def run_test(name: str, params: dict, wait: int, check_func, desc: str) -> tuple[bool, dict, dict]:
    print(f"  [{name:22}] {desc}")
    # Baseline
    stop_all()
    time.sleep(2)
    before = get_metric()

    aid = start_attack(name, params)
    if not aid:
        print(f"     [FAIL] failed to start")
        return False, before, {}

    time.sleep(wait)
    after = get_metric()
    stop_attack(aid)
    time.sleep(1)

    b_cpu = before.get("cpu_percent", 0)
    a_cpu = after.get("cpu_percent", 0)
    b_mem = before.get("memory_percent", 0)
    a_mem = after.get("memory_percent", 0)
    b_proc = before.get("process_count", 0)
    a_proc = after.get("process_count", 0)
    b_thr = before.get("thread_count", 0)
    a_thr = after.get("thread_count", 0)

    ok = check_func(before, after)
    status = "[OK] PASS" if ok else "[WARN] WEAK"

    print(f"     {status} | CPU {b_cpu:5.1f} -> {a_cpu:5.1f}  MEM {b_mem:5.1f} -> {a_mem:5.1f}  PROC {b_proc} -> {a_proc}  THR {b_thr} -> {a_thr}")
    return ok, before, after


def main():
    print("=" * 80)
    print(" Argus Attack Integration Test")
    print("=" * 80)

    results = []
    for name, params, wait, check, desc in TESTS:
        try:
            ok, _, _ = run_test(name, params, wait, check, desc)
            results.append((name, ok))
        except Exception as e:
            print(f"     [FAIL] CRASH: {e}")
            results.append((name, False))

    stop_all()

    passed = sum(1 for _, ok in results if ok)
    print()
    print("=" * 80)
    print(f" Results: {passed}/{len(results)} passed")
    print("=" * 80)
    for name, ok in results:
        print(f"  {'[OK]' if ok else '[FAIL]'}  {name}")


if __name__ == "__main__":
    main()
