"""
Direct impact test — measures system metrics DIRECTLY via psutil,
independent of the server's monitor. Proves attacks work.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import psutil
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


ATTACKER = "http://127.0.0.1:8001"


def get_psutil_metrics() -> dict:
    """Measure directly via psutil — no server dependency."""
    # Warmup for accurate CPU reading
    psutil.cpu_percent(interval=None)
    time.sleep(0.2)

    vm = psutil.virtual_memory()
    try:
        disk = psutil.disk_usage("C:\\")
    except Exception:
        disk = psutil.disk_usage("/")

    procs = list(psutil.process_iter(["pid"]))
    threads = sum(
        (p.num_threads() for p in procs if p.is_running()),
        start=0,
    ) if procs else 0

    return {
        "cpu": round(psutil.cpu_percent(interval=0.3), 1),
        "memory_pct": round(vm.percent, 1),
        "memory_used_gb": round(vm.used / (1024 ** 3), 2),
        "disk_pct": round(disk.percent, 1),
        "procs": len(procs),
        "threads": threads,
    }


def start_attack(name: str, params: dict) -> str | None:
    try:
        r = requests.post(f"{ATTACKER}/api/attacks/{name}/start", json=params, timeout=10)
        if r.ok:
            return r.json().get("id")
        print(f"  [start failed] {r.status_code} {r.text[:200]}")
    except Exception as e:
        print(f"  [error] {e}")
    return None


def stop_all() -> None:
    try:
        requests.post(f"{ATTACKER}/api/attacks/stop_all", timeout=10)
    except Exception:
        pass


def wait_for_recovery(baseline_cpu: float = 40, baseline_mem: float = 75, max_wait: int = 30) -> dict:
    """Wait for system to recover to baseline after an attack."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        m = get_psutil_metrics()
        if m["cpu"] < baseline_cpu and m["memory_pct"] < baseline_mem + 5:
            return m
        time.sleep(2)
    return get_psutil_metrics()


def run_case(name: str, params: dict, wait_sec: int, check_keys: list[str]) -> dict:
    print(f"\n>>> {name} (params={params})")

    # Stop any previous + recover
    stop_all()
    before = wait_for_recovery()
    print(f"  before: CPU={before['cpu']}% MEM={before['memory_pct']}% PROCS={before['procs']} THR={before['threads']}")

    aid = start_attack(name, params)
    if not aid:
        print(f"  SKIP: failed to start")
        return {"ok": False, "before": before, "after": {}}

    # Sample peak during attack
    peaks = {k: 0 for k in ("cpu", "memory_pct", "memory_used_gb", "disk_pct", "procs", "threads")}
    for sec in range(wait_sec):
        time.sleep(1)
        m = get_psutil_metrics()
        for k in peaks:
            peaks[k] = max(peaks[k], m[k])
        if sec % 3 == 0:
            print(f"  [t={sec+1:2}s] CPU={m['cpu']:5.1f}% MEM={m['memory_pct']:5.1f}% PROCS={m['procs']} THR={m['threads']}")

    stop_all()
    print(f"  PEAK  : CPU={peaks['cpu']}% MEM={peaks['memory_pct']}% PROCS={peaks['procs']} THR={peaks['threads']}")

    # Compute deltas
    deltas = {k: round(peaks[k] - before[k], 2) for k in peaks}
    print(f"  DELTA : CPU={deltas['cpu']:+} MEM={deltas['memory_pct']:+} PROCS={deltas['procs']:+} THR={deltas['threads']:+}")

    # Verdict
    verdict_parts = []
    for key in check_keys:
        if key == "cpu" and deltas["cpu"] > 25:
            verdict_parts.append(f"CPU+{deltas['cpu']}")
        if key == "memory_pct" and deltas["memory_pct"] > 3:
            verdict_parts.append(f"MEM+{deltas['memory_pct']}")
        if key == "procs" and deltas["procs"] > 3:
            verdict_parts.append(f"PROCS+{deltas['procs']}")
        if key == "threads" and deltas["threads"] > 40:
            verdict_parts.append(f"THR+{deltas['threads']}")

    if verdict_parts:
        print(f"  [OK]  {', '.join(verdict_parts)}")
        return {"ok": True, "before": before, "peaks": peaks, "deltas": deltas}
    else:
        print(f"  [WEAK] expected impact on {check_keys} not detected")
        return {"ok": False, "before": before, "peaks": peaks, "deltas": deltas}


def main() -> None:
    print("=" * 78)
    print(" Direct Attack Impact Test (via psutil)")
    print("=" * 78)

    cases = [
        ("cpu_spike",       {"cores": 4, "duration": 15},        12, ["cpu"]),
        ("ram_flood",       {"size_mb": 1500, "duration": 15},   12, ["memory_pct"]),
        ("disk_fill",       {"size_mb": 500, "duration": 15},    10, []),
        ("cryptomining_sim",{"cores": 2, "duration": 15},        10, ["cpu"]),
        ("thread_flood",    {"count": 300, "duration": 15},       8, ["threads"]),
        ("fork_bomb",       {"count": 15, "duration": 15},       10, ["procs"]),
        ("slow_creep",      {"duration": 20},                    18, ["cpu"]),
        ("memory_leak",     {"leak_rate_mb_per_sec": 30, "duration": 15}, 12, ["memory_pct"]),
        ("swap_thrash",     {"size_mb": 800, "duration": 15},    12, ["memory_pct"]),
    ]

    results = []
    for name, params, wait, checks in cases:
        try:
            r = run_case(name, params, wait, checks)
            results.append((name, r["ok"]))
        except Exception as e:
            print(f"  CRASH: {e}")
            results.append((name, False))

    stop_all()

    print()
    print("=" * 78)
    print(" Summary")
    print("=" * 78)
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'[OK]  ' if ok else '[WEAK]'} {name}")
    print(f"\n  Total: {passed}/{len(results)} attacks show measurable impact")


if __name__ == "__main__":
    main()
